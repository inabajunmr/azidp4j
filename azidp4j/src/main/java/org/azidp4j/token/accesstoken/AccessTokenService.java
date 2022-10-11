package org.azidp4j.token.accesstoken;

import java.util.Optional;

public interface AccessTokenService {

    AccessToken issue(String sub, String scope, String clientId);

    Optional<AccessToken> introspect(String token);

    void revoke(String token);

    void revokeByAuthorizationCode(String authorizationCode);
}
