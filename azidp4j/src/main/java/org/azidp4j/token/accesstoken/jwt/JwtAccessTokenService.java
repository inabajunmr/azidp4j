package org.azidp4j.token.accesstoken.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.util.MapUtil;

public class JwtAccessTokenService implements AccessTokenService {

    private final JWKSet jwkSet;
    private final JWSIssuer jwsIssuer;
    private final String issuer;
    private final Supplier<String> kidSupplier;

    public JwtAccessTokenService(JWKSet jwkSet, String issuer, Supplier<String> kidSupplier) {
        this.jwkSet = jwkSet;
        this.jwsIssuer = new JWSIssuer(jwkSet);
        this.issuer = issuer;
        this.kidSupplier = kidSupplier;
    }

    @Override
    public AccessToken issue(
            String sub,
            String scope,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims =
                MapUtil.nullRemovedMap(
                        "iss",
                        issuer,
                        "sub",
                        sub,
                        "aud",
                        audience,
                        "exp",
                        exp,
                        "iat",
                        iat,
                        "jti",
                        jti,
                        "client_id",
                        clientId,
                        "scope",
                        scope,
                        "authorization_code",
                        authorizationCode);
        var jwt = jwsIssuer.issue(kidSupplier.get(), "at+jwt", claims).serialize();
        return new AccessToken(jwt, sub, scope, clientId, audience, exp, iat, authorizationCode);
    }

    @Override
    public Optional<AccessToken> introspect(String token) {
        try {
            // https://datatracker.ietf.org/doc/html/rfc9068#section-4
            var jws = JWSObject.parse(token);

            // verify signature
            var key = jwkSet.getKeyByKeyId(jws.getHeader().getKeyID());
            if (key == null) {
                return Optional.empty();
            }
            if (key instanceof ECKey) {
                if (!jws.verify(new ECDSAVerifier((ECKey) key))) {
                    return Optional.empty();
                }
            } else if (key instanceof RSAKey) {
                if (!jws.verify(new RSASSAVerifier((RSAKey) key))) {
                    return Optional.empty();
                }
            } else {
                return Optional.empty();
            }
            if (!Objects.equals(jws.getHeader().toJSONObject().get("typ"), "at+jwt")) {
                return Optional.empty();
            }
            if (!Objects.equals(jws.getPayload().toJSONObject().get("iss"), issuer)) {
                return Optional.empty();
            }
            if ((Long) jws.getPayload().toJSONObject().get("exp")
                    < Instant.now().getEpochSecond()) {
                return Optional.empty();
            }

            var payload = jws.getPayload().toJSONObject();
            var sub = payload.containsKey("sub") ? (String) payload.get("sub") : null;
            var scope = payload.containsKey("scope") ? (String) payload.get("scope") : null;
            var clientId =
                    payload.containsKey("client_id") ? (String) payload.get("client_id") : null;
            var aud =
                    payload.containsKey("aud")
                            ? new HashSet<>(((List<String>) payload.get("aud")))
                            : null;
            var authorizationCode =
                    payload.containsKey("authorization_code")
                            ? (String) payload.get("authorization_code")
                            : null;
            var exp = payload.containsKey("exp") ? (Long) payload.get("exp") : null;
            var iat = payload.containsKey("iat") ? (Long) payload.get("iat") : null;
            return Optional.of(
                    new AccessToken(token, sub, scope, clientId, aud, exp, iat, authorizationCode));
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(String token) {
        throw new AssertionError("JwtAccessTokenService doesn't support revoke");
    }

    @Override
    public void revokeByAuthorizationCode(String authorizationCode) {
        throw new AssertionError("JwtAccessTokenService doesn't support revokeByAuthorizationCode");
    }
}
