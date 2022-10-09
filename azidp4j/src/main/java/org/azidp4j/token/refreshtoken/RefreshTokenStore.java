package org.azidp4j.token.refreshtoken;

import java.util.Optional;

public interface RefreshTokenStore {

    void save(RefreshToken token);

    Optional<RefreshToken> consume(String token);

    void removeByAuthorizationCode(String authorizationCode);
}
