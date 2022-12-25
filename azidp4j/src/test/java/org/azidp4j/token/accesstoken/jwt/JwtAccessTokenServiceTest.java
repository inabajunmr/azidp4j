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
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class JwtAccessTokenServiceTest {

    final RSAKey rs256 =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
    final ECKey es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    final JWKSet jwks = new JWKSet(List.of(rs256, es256));
    final Supplier<String> kidSupplier = () -> "abc";
    final JwtAccessTokenService sut = new JwtAccessTokenService(jwks, "issuer", kidSupplier);

    JwtAccessTokenServiceTest() throws JOSEException {}

    @Test
    void success() {
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub",
                        "scope1 scope2",
                        "{\"userinfo\":{\"name\":{\"essential\":true}}}",
                        "client id",
                        exp,
                        iat,
                        Set.of("audience"),
                        "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);
        assertEquals("code", issued.authorizationCode);

        var introspected = sut.introspect(issued.token).get();
        assertEquals("sub", introspected.sub);
        assertEquals("scope1 scope2", introspected.scope);
        assertEquals("client id", introspected.clientId);
        assertEquals(Set.of("audience"), introspected.audience);
        assertEquals(exp, introspected.expiresAtEpochSec);
        assertEquals(iat, introspected.issuedAtEpochSec);
        assertEquals("code", introspected.authorizationCode);
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
                        "sub",
                        "scope1 scope2",
                        null,
                        "client id",
                        exp,
                        iat,
                        Set.of("audience"),
                        "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);
        assertEquals("code", issued.authorizationCode);
        JwtAccessTokenService wrongKeyService =
                new JwtAccessTokenService(new JWKSet(List.of(es256)), "issuer", () -> "abc");

        // exercise
        var introspected = wrongKeyService.introspect(issued.token);

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
                        "sub",
                        "scope1 scope2",
                        null,
                        "client id",
                        exp,
                        iat,
                        Set.of("audience"),
                        "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);
        assertEquals("code", issued.authorizationCode);

        var introspected = sut.introspect(issued.token);
        assertFalse(introspected.isPresent());
    }

    @Test
    void invalidIssuer() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        JwtAccessTokenService service = new JwtAccessTokenService(jwks, "invalid", kidSupplier);

        var issued =
                service.issue(
                        "sub",
                        "scope1 scope2",
                        null,
                        "client id",
                        exp,
                        iat,
                        Set.of("audience"),
                        "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);
        assertEquals("code", issued.authorizationCode);

        var introspected = sut.introspect(issued.token);
        assertFalse(introspected.isPresent());
    }
}
