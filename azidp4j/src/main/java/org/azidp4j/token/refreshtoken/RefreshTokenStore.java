package org.azidp4j.token.refreshtoken;

public interface RefreshTokenStore {

    void save(RefreshToken token);

    RefreshToken consume(String token);

    RefreshToken removeByAuthorizationCode(String authorizationCode);
}
