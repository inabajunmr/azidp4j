package org.azidp4j.token.refreshtoken.jwt;

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
import java.util.Set;
import java.util.function.Supplier;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.util.MapUtil;
import org.junit.jupiter.api.Test;

class JwtRefreshTokenServiceTest {

    final RSAKey rs256 =
            new RSAKeyGenerator(2048).keyID("abc").algorithm(new Algorithm("RS256")).generate();
    final ECKey es256 =
            new ECKeyGenerator(Curve.P_256)
                    .keyID("123")
                    .algorithm(new Algorithm("ES256"))
                    .generate();
    final JWKSet jwks = new JWKSet(List.of(rs256, es256));
    final JWSIssuer jwsIssuer = new JWSIssuer(jwks);
    final Supplier<String> kidSupplier = () -> "abc";
    final JwtRefreshTokenService sut = new JwtRefreshTokenService(jwks, "issuer", kidSupplier);

    JwtRefreshTokenServiceTest() throws JOSEException {}

    @Test
    void success() {
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        var issued =
                sut.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);

        var introspected = sut.introspect(issued.token).get();
        assertEquals("sub", introspected.sub);
        assertEquals("scope1 scope2", introspected.scope);
        assertEquals("client id", introspected.clientId);
        assertEquals(Set.of("audience"), introspected.audience);
        assertEquals(exp, introspected.expiresAtEpochSec);
        assertEquals(iat, introspected.issuedAtEpochSec);
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
                                .type(new JOSEObjectType("rt+jwt"))
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
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);
        JwtRefreshTokenService wrongKeyService =
                new JwtRefreshTokenService(new JWKSet(List.of(es256)), "issuer", () -> "abc");

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
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);

        var introspected = sut.introspect(issued.token);
        assertFalse(introspected.isPresent());
    }

    @Test
    void invalidIssuer() {
        // setup
        var exp = Instant.now().getEpochSecond() + 100;
        var iat = Instant.now().getEpochSecond();
        JwtRefreshTokenService service = new JwtRefreshTokenService(jwks, "invalid", kidSupplier);

        var issued =
                service.issue(
                        "sub", "scope1 scope2", "client id", exp, iat, Set.of("audience"), "code");
        assertEquals("sub", issued.sub);
        assertEquals("scope1 scope2", issued.scope);
        assertEquals("client id", issued.clientId);
        assertEquals(Set.of("audience"), issued.audience);
        assertEquals(exp, issued.expiresAtEpochSec);
        assertEquals(iat, issued.issuedAtEpochSec);

        var introspected = sut.introspect(issued.token);
        assertFalse(introspected.isPresent());
    }
}
