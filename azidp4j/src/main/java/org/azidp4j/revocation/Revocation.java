package org.azidp4j.revocation;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.azidp4j.client.ClientStore;
import org.azidp4j.revocation.request.InternalRevocationRequest;
import org.azidp4j.revocation.response.RevocationResponse;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenService;

public class Revocation {

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;

    private final ClientStore clientStore;

    public Revocation(
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            ClientStore clientStore) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.clientStore = clientStore;
    }

    public RevocationResponse revoke(InternalRevocationRequest request) {
        if (request.tokenTypeHint != null
                && !Set.of("access_token", "refresh_token").contains(request.tokenTypeHint)) {
            return new RevocationResponse(400, Map.of("error", "unsupported_token_type"));
        }
        if (request.token == null) {
            return new RevocationResponse(200, Map.of());
        }
        if (Objects.equals(request.tokenTypeHint, "refresh_token")) {
            var rtOpt = refreshTokenService.introspect(request.token);
            if (rtOpt.isPresent()) {
                return revokeRefreshToken(request, rtOpt);
            }
        }

        var atOpt = accessTokenService.introspect(request.token);
        if (atOpt.isPresent()) {
            return revokeAccessToken(request, atOpt);
        }

        var rtOpt = refreshTokenService.introspect(request.token);
        if (rtOpt.isPresent()) {
            return revokeRefreshToken(request, rtOpt);
        }

        return new RevocationResponse(200, Map.of());
    }

    private RevocationResponse revokeAccessToken(
            InternalRevocationRequest request, Optional<AccessToken> atOpt) {
        var at = atOpt.get();
        var client = clientStore.find(at.getClientId());
        if (!client.isPresent()) {
            return new RevocationResponse(200, Map.of());
        }

        if (!client.get().isConfidentialClient()) {
            accessTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (at.getClientId().equals(request.authenticatedClientId)) {
            accessTokenService.revoke(request.token);
        }
        return new RevocationResponse(200, Map.of());
    }

    private RevocationResponse revokeRefreshToken(
            InternalRevocationRequest request, Optional<RefreshToken> rtOpt) {
        var rt = rtOpt.get();
        var client = clientStore.find(rt.clientId);
        if (!client.isPresent()) {
            return new RevocationResponse(200, Map.of());
        }

        if (!client.get().isConfidentialClient()) {
            refreshTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (rt.clientId.equals(request.authenticatedClientId)) {
            refreshTokenService.revoke(request.token);
        }
        return new RevocationResponse(200, Map.of());
    }
}
