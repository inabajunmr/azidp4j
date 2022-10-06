// package org.azidp4j.token.accesstoken;
//
// import com.nimbusds.jose.JWSObject;
// import com.nimbusds.jose.jwk.JWKSet;
// import java.time.Instant;
// import java.util.Map;
// import java.util.Set;
// import java.util.UUID;
// import org.azidp4j.AzIdPConfig;
// import org.azidp4j.jwt.JWSIssuer;
// import org.azidp4j.scope.ScopeAudienceMapper;
//
// public class JwtAccessTokenIssuer {
//
//    private final AzIdPConfig config;
//
//    private final JWSIssuer jwsIssuer;
//
//    private final ScopeAudienceMapper scopeAudienceMapper;
//
//    public JwtAccessTokenIssuer(
//            AzIdPConfig config, JWKSet jwkSet, ScopeAudienceMapper scopeAudienceMapper) {
//        this.config = config;
//        this.jwsIssuer = new JWSIssuer(jwkSet);
//        this.scopeAudienceMapper = scopeAudienceMapper;
//    }
//
//    public JWSObject issue(String sub, String clientId, String scope) {
//        return this.issue(sub, clientId, scope, scopeAudienceMapper.map(scope));
//    }
//
//    public JWSObject issue(String sub, String clientId, String scope, Set<String> audience) {
//        var jti = UUID.randomUUID().toString();
//        Map<String, Object> claims =
//                Map.of(
//                        "iss",
//                        config.issuer,
//                        "sub",
//                        sub,
//                        "aud",
//                        audience,
//                        "exp",
//                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
//                        "iat",
//                        Instant.now().getEpochSecond(),
//                        "jti",
//                        jti,
//                        "client_id",
//                        clientId,
//                        "scope",
//                        scope);
//        return jwsIssuer.issue(config.accessTokenKid, "at+JWT", claims);
//    }
// }
