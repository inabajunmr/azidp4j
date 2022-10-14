package org.azidp4j.token.accesstoken.jwt;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class JwtAccessTokenServiceTest {

    RSAKey rs256 =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
    ECKey es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    JWKSet jwks = new JWKSet(List.of(rs256, es256));
    JWSIssuer jwsIssuer = new JWSIssuer(jwks);
    Supplier<String> kidSupplier = () -> "abc";
    JwtAccessTokenService sut = new JwtAccessTokenService(jwks, jwsIssuer, "issuer", kidSupplier);

    JwtAccessTokenServiceTest() throws JOSEException {}

    @Test
    void success() {
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.getSub());
        assertEquals("scope1 scope2", issued.getScope());
        assertEquals("client id", issued.getClientId());
        assertEquals(Set.of("audience"), issued.getAudience());
        assertEquals(exp, issued.getExpiresAtEpochSec());
        assertEquals(iat, issued.getIssuedAtEpochSec());
        assertEquals("code", issued.getAuthorizationCode());

        var introspected = sut.introspect(issued.getToken()).get();
        assertEquals("sub", introspected.getSub());
        assertEquals("scope1 scope2", introspected.getScope());
        assertEquals("client id", introspected.getClientId());
        assertEquals(Set.of("audience"), introspected.getAudience());
        assertEquals(exp, introspected.getExpiresAtEpochSec());
        assertEquals(iat, introspected.getIssuedAtEpochSec());
        assertEquals("code", introspected.getAuthorizationCode());
    }

    @Test
    void invalidJwt() {
        var introspected = sut.introspect("invalid");
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
        var introspected = sut.introspect(none.serialize());
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
        ECKey wrongKey = new ECKeyGenerator(Curve.P_256).generate();
        JWSSigner signer = new ECDSASigner(wrongKey);
        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .keyID(wrongKey.getKeyID())
                                .type(new JOSEObjectType("at+jwt"))
                                .build(),
                        new Payload(claims));
        jwsObject.sign(signer);

        // exercise
        var introspected = sut.introspect(jwsObject.serialize());

        // verify
        assertFalse(introspected.isPresent());
    }

    @Test
    void keyNotFound() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.getSub());
        assertEquals("scope1 scope2", issued.getScope());
        assertEquals("client id", issued.getClientId());
        assertEquals(Set.of("audience"), issued.getAudience());
        assertEquals(exp, issued.getExpiresAtEpochSec());
        assertEquals(iat, issued.getIssuedAtEpochSec());
        assertEquals("code", issued.getAuthorizationCode());
        JwtAccessTokenService wrongKeyService =
                new JwtAccessTokenService(
                        new JWKSet(List.of(es256)), jwsIssuer, "issuer", () -> "abc");

        // exercise
        var introspected = wrongKeyService.introspect(issued.getToken());

        // verify
        assertFalse(introspected.isPresent());
    }

    @Test
    void expired() {
        // setup
        var exp = Instant.now().getEpochSecond() - 100;
        var iat = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.getSub());
        assertEquals("scope1 scope2", issued.getScope());
        assertEquals("client id", issued.getClientId());
        assertEquals(Set.of("audience"), issued.getAudience());
        assertEquals(exp, issued.getExpiresAtEpochSec());
        assertEquals(iat, issued.getIssuedAtEpochSec());
        assertEquals("code", issued.getAuthorizationCode());

        var introspected = sut.introspect(issued.getToken());
        assertFalse(introspected.isPresent());
    }

    @Test
    void invalidIssuer() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        JwtAccessTokenService service =
                new JwtAccessTokenService(jwks, jwsIssuer, "invalid", kidSupplier);

        var issued =
                service.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.getSub());
        assertEquals("scope1 scope2", issued.getScope());
        assertEquals("client id", issued.getClientId());
        assertEquals(Set.of("audience"), issued.getAudience());
        assertEquals(exp, issued.getExpiresAtEpochSec());
        assertEquals(iat, issued.getIssuedAtEpochSec());
        assertEquals("code", issued.getAuthorizationCode());

        var introspected = sut.introspect(issued.getToken());
        assertFalse(introspected.isPresent());
    }
}
