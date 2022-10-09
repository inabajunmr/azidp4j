package org.azidp4j.token.accesstoken;

import java.util.Optional;

public interface AccessTokenStore {

    void save(InMemoryAccessToken token);

    Optional<InMemoryAccessToken> find(String token);

    InMemoryAccessToken remove(String token);

    InMemoryAccessToken removeByAuthorizationCode(String code);
}
