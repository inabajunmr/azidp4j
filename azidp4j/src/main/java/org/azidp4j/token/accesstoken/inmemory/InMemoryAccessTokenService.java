package org.azidp4j.token.accesstoken.inmemory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;

public class InMemoryAccessTokenService implements AccessTokenService {

    private final InMemoryAccessTokenStore accessTokenStore;

    public InMemoryAccessTokenService(InMemoryAccessTokenStore accessTokenStore) {
        this.accessTokenStore = accessTokenStore;
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
        var at =
                new AccessToken(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        clientId,
                        audience,
                        exp,
                        iat,
                        authorizationCode);
        accessTokenStore.save(at);
        return at;
    }

    @Override
    public Optional<AccessToken> introspect(String token) {
        return accessTokenStore.find(token);
    }

    @Override
    public void revoke(String token) {
        accessTokenStore.remove(token);
    }

    @Override
    public void revokeByAuthorizationCode(String authorizationCode) {
        accessTokenStore.removeByAuthorizationCode(authorizationCode);
    }
}
