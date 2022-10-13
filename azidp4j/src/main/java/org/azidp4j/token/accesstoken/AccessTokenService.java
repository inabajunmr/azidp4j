package org.azidp4j.token.accesstoken;

import java.util.Optional;
import java.util.Set;

public interface AccessTokenService {

    AccessToken issue(
            String sub,
            String scope,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode);

    Optional<AccessToken> introspect(String token);

    void revoke(String token);

    void revokeByAuthorizationCode(String authorizationCode);
}
