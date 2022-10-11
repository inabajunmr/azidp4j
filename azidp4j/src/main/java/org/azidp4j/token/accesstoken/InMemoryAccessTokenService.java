package org.azidp4j.token.accesstoken;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.scope.ScopeAudienceMapper;

public class InMemoryAccessTokenService implements AccessTokenService {

    private final AzIdPConfig config;

    private final ScopeAudienceMapper scopeAudienceMapper;

    private final AccessTokenStore accessTokenStore;

    public InMemoryAccessTokenService(
            AzIdPConfig config,
            ScopeAudienceMapper scopeAudienceMapper,
            AccessTokenStore accessTokenStore) {
        this.config = config;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.accessTokenStore = accessTokenStore;
    }

    @Override
    public AccessToken issue(String sub, String scope, String clientId) {
        var at =
                new InMemoryAccessToken(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        clientId,
                        scopeAudienceMapper.map(scope),
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
                        Instant.now().getEpochSecond());
        accessTokenStore.save(at);
        return at;
    }

    @Override
    public AccessToken issue(String sub, String scope, String clientId, String authorizationCode) {
        var at =
                new InMemoryAccessToken(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        clientId,
                        scopeAudienceMapper.map(scope),
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
                        Instant.now().getEpochSecond(),
                        authorizationCode);
        accessTokenStore.save(at);
        return at;
    }

    @Override
    public AccessToken issue(String sub, String scope, String clientId, Set<String> audience) {
        var at =
                new InMemoryAccessToken(
                        UUID.randomUUID().toString(),
                        sub,
                        scope,
                        clientId,
                        audience,
                        Instant.now().getEpochSecond() + config.accessTokenExpirationSec,
                        Instant.now().getEpochSecond());
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
