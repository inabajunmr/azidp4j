package org.azidp4j.token.accesstoken.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;

public class JwtAccessTokenService implements AccessTokenService {

    private final JWKSet jwkSet;
    private final JWSIssuer jwsIssuer;
    private final String issuer;
    private final Supplier<String> kidSuplier;

    public JwtAccessTokenService(
            JWKSet jwkSet, JWSIssuer jwsIssuer, String issuer, Supplier<String> kidSuplier) {
        this.jwkSet = jwkSet;
        this.jwsIssuer = jwsIssuer;
        this.issuer = issuer;
        this.kidSuplier = kidSuplier;
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
                Map.of(
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
                        scope);
        var jwt = jwsIssuer.issue(kidSuplier.get(), "at+JWT", claims).serialize();
        return new AccessToken(jwt, sub, scope, clientId, audience, exp, iat, authorizationCode);
    }

    @Override
    public Optional<AccessToken> introspect(String token) {
        try {
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

            // TODO https://datatracker.ietf.org/doc/html/rfc9068#section-4
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }

        return Optional.empty();
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
