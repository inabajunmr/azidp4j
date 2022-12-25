package org.azidp4j.token.refreshtoken.inmemory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenService;

public class InMemoryRefreshTokenService implements RefreshTokenService {

    private final InMemoryRefreshTokenStore refreshTokenStore;

    public InMemoryRefreshTokenService(InMemoryRefreshTokenStore refreshTokenStore) {
        this.refreshTokenStore = refreshTokenStore;
    }

    @Override
    public RefreshToken issue(
            String sub,
            String scope,
            String claims,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode) {
        var rt =
                new RefreshToken(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        claims,
                        clientId,
                        audience,
                        exp,
                        iat,
                        authorizationCode);
        refreshTokenStore.save(rt);
        return rt;
    }

    @Override
    public Optional<RefreshToken> introspect(String token) {
        return refreshTokenStore.find(token);
    }

    @Override
    public Optional<RefreshToken> consume(String token) {
        return refreshTokenStore.consume(token);
    }

    @Override
    public void revoke(String token) {
        refreshTokenStore.consume(token);
    }

    @Override
    public void revokeByAuthorizationCode(String authorizationCode) {
        refreshTokenStore.removeByAuthorizationCode(authorizationCode);
    }
}
