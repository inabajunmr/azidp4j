package org.azidp4j.token;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.scope.ScopeAudienceMapper;

public class AccessTokenIssuer {

    private final AzIdPConfig config;

    private final JWSIssuer jwsIssuer;

    private final ScopeAudienceMapper scopeAudienceMapper;

    public AccessTokenIssuer(
            AzIdPConfig config, JWKSet jwkSet, ScopeAudienceMapper scopeAudienceMapper) {
        this.config = config;
        this.jwsIssuer = new JWSIssuer(jwkSet);
        this.scopeAudienceMapper = scopeAudienceMapper;
    }

    public JWSObject issue(String sub, String clientId, String scope) {
        var jti = UUID.randomUUID().toString();
        Map<String, Object> claims =
                Map.of(
                        "iss",
                        config.issuer,
                        "sub",
                        sub,
                        "aud",
                        scopeAudienceMapper.map(scope),
                        "exp",
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
                        "iat",
                        Instant.now().getEpochSecond(),
                        "jti",
                        jti,
                        "client_id",
                        clientId,
                        "scope",
                        scope);
        return jwsIssuer.issue(config.accessTokenKid, claims);
    }
}
