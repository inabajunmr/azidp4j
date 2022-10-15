package org.azidp4j.token.refreshtoken;

import java.util.Optional;
import java.util.Set;

public interface RefreshTokenService {

    RefreshToken issue(
            String sub,
            String scope,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode);

    Optional<RefreshToken> introspect(String token);

    Optional<RefreshToken> consume(String token);

    void revoke(String token);

    void revokeByAuthorizationCode(String authorizationCode);
}
