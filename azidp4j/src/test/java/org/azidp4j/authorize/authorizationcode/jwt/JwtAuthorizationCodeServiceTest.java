package org.azidp4j.authorize.authorizationcode.jwt;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class JwtAuthorizationCodeServiceTest {

    final RSAKey rs256 =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
    final ECKey es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    final JWKSet jwks = new JWKSet(List.of(rs256, es256));
    final Supplier<String> kidSupplier = () -> "abc";
    final JwtAuthorizationCodeService sut =
            new JwtAuthorizationCodeService(jwks, "issuer", kidSupplier);

    JwtAuthorizationCodeServiceTest() throws JOSEException {}

    @Test
    void success() {
        var exp = Instant.now().getEpochSecond() + 100;
        var authTime = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub",
                        "scope1 scope2",
                        "client id",
                        "http://example.com",
                        "state",
                        authTime,
                        "nonce",
                        "challenge",
                        CodeChallengeMethod.PLAIN,
                        exp);
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals("http://example.com", issued.redirectUri);
        assertEquals("state", issued.state);
        assertEquals(authTime, issued.authTime);
        assertEquals("nonce", issued.nonce);
        assertEquals("challenge", issued.codeChallenge);
        assertEquals(CodeChallengeMethod.PLAIN, issued.codeChallengeMethod);
        assertEquals(exp, issued.expiresAtEpochSec);

        var introspected = sut.consume(issued.code).get();
        assertEquals("sub", introspected.sub);
        assertEquals("scope1 scope2", introspected.scope);
        assertEquals("client id", introspected.clientId);
        assertEquals(exp, introspected.expiresAtEpochSec);
        assertEquals("http://example.com", introspected.redirectUri);
        assertEquals("state", introspected.state);
        assertEquals(authTime, introspected.authTime);
        assertEquals("nonce", introspected.nonce);
        assertEquals("challenge", introspected.codeChallenge);
        assertEquals(CodeChallengeMethod.PLAIN, introspected.codeChallengeMethod);
        assertEquals(exp, introspected.expiresAtEpochSec);
    }

    @Test
    void invalidJwt() {
        var introspected = sut.consume("invalid");
        assertFalse(introspected.isPresent());
    }

    @Test
    void noSignature() {
        Map<String, Object> claims =
                MapUtil.nullRemovedMap(
                        "iss",
                        "issuer",
                        "sub",
                        "sub",
                        "aud",
                        "audience",
                        "exp",
                        Instant.now().getEpochSecond() + 100,
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        "jti",
                        "client_id",
                        "clientId",
                        "scope",
                        "scope1 scope2",
                        "authorization_code",
                        "authorizationCode");
        var none = new PlainObject(new Payload(claims));
        var introspected = sut.consume(none.serialize());
        assertFalse(introspected.isPresent());
    }

    @Test
    void wrongSignature() throws JOSEException {
        // setup
        Map<String, Object> claims =
                MapUtil.nullRemovedMap(
                        "iss",
                        "issuer",
                        "sub",
                        "sub",
                        "exp",
                        Instant.now().getEpochSecond(),
                        "jti",
                        "jti",
                        "client_id",
                        "clientId",
                        "redirect_uri",
                        "http://example.com",
                        "scope",
                        "scope",
                        "state",
                        "state",
                        "nonce",
                        "nonce",
                        "auth_time",
                        Instant.now().getEpochSecond(),
                        "code_challenge",
                        "codeChallenge",
                        "code_challenge_method",
                        CodeChallengeMethod.PLAIN.name());
        ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSSigner signer = new ECDSASigner(wrongKey);
        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .keyID(wrongKey.getKeyID())
                                .type(new JOSEObjectType("ac+jwt"))
                                .build(),
                        new Payload(claims));
        jwsObject.sign(signer);

        // exercise
        var introspected = sut.consume(jwsObject.serialize());

        // verify
        assertFalse(introspected.isPresent());
    }

    @Test
    void keyNotFound() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var authTime = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub",
                        "scope1 scope2",
                        "client id",
                        "http://example.com",
                        "state",
                        authTime,
                        "nonce",
                        "challenge",
                        CodeChallengeMethod.PLAIN,
                        exp);
        assertEquals("sub", issued.sub);

        // exercise
        JwtAccessTokenService wrongKeyService =
                new JwtAccessTokenService(new JWKSet(List.of(es256)), "issuer", () -> "abc");

        // exercise
        var introspected = wrongKeyService.introspect(issued.code);

        // verify
        assertFalse(introspected.isPresent());
    }

    @Test
    void expired() {
        // setup
        var exp = Instant.now().getEpochSecond() - 100;
        var authTime = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub",
                        "scope1 scope2",
                        "client id",
                        "http://example.com",
                        "state",
                        authTime,
                        "nonce",
                        "challenge",
                        CodeChallengeMethod.PLAIN,
                        exp);
        assertEquals("sub", issued.sub);

        var introspected = sut.consume(issued.code);
        assertFalse(introspected.isPresent());
    }

    @Test
    void invalidIssuer() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var authTime = Instant.now().getEpochSecond();
        JwtAuthorizationCodeService service =
                new JwtAuthorizationCodeService(jwks, "invalid", kidSupplier);
        var issued =
                service.issue(
                        "sub",
                        "scope1 scope2",
                        "client id",
                        "http://example.com",
                        "state",
                        authTime,
                        "nonce",
                        "challenge",
                        CodeChallengeMethod.PLAIN,
                        exp);
        assertEquals("sub", issued.sub);

        var introspected = sut.consume(issued.code);
        assertFalse(introspected.isPresent());
    }
}
