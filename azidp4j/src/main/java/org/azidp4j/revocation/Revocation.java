package org.azidp4j.revocation;

import java.util.Map;
import java.util.Objects;
import org.azidp4j.client.ClientStore;
import org.azidp4j.revocation.request.InternalRevocationRequest;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.revocation.request.RevocationRequestParser;
import org.azidp4j.revocation.request.TokenTypeHint;
import org.azidp4j.revocation.response.RevocationResponse;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenService;

public class Revocation {

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;

    private final ClientStore clientStore;

    private final RevocationRequestParser revocationRequestParser = new RevocationRequestParser();

    public Revocation(
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            ClientStore clientStore) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.clientStore = clientStore;
    }

    public RevocationResponse revoke(RevocationRequest request) {
        InternalRevocationRequest req;
        try {
            req = revocationRequestParser.parse(request);
        } catch (IllegalArgumentException e) {
            return new RevocationResponse(400, Map.of("error", "invalid_request"));
        }
        var hint = TokenTypeHint.access_token;
        if (req.tokenTypeHint != null) {
            try {
                hint = TokenTypeHint.of(req.tokenTypeHint);
            } catch (IllegalArgumentException e) {
                return new RevocationResponse(400, Map.of("error", "invalid_request"));
            }
        }
        if (req.token == null) {
            return new RevocationResponse(200, Map.of());
        }
        if (Objects.equals(hint, TokenTypeHint.refresh_token)) {
            var rtOpt = refreshTokenService.introspect(req.token);
            if (rtOpt.isPresent()) {
                return revokeRefreshToken(req, rtOpt.get());
            }
        }

        var atOpt = accessTokenService.introspect(req.token);
        if (atOpt.isPresent()) {
            return revokeAccessToken(req, atOpt.get());
        }

        var rtOpt = refreshTokenService.introspect(req.token);
        if (rtOpt.isPresent()) {
            return revokeRefreshToken(req, rtOpt.get());
        }

        return new RevocationResponse(200, Map.of());
    }

    private RevocationResponse revokeAccessToken(
            InternalRevocationRequest request, AccessToken at) {
        var client = clientStore.find(at.clientId);
        if (client.isEmpty()) {
            // no client token is useless
            accessTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (!client.get().isConfidentialClient()) {
            // public client doesn't require client authentication for revocation.
            accessTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (Objects.equals(at.clientId, request.authenticatedClientId)) {
            accessTokenService.revoke(request.token);
        }
        return new RevocationResponse(200, Map.of());
    }

    private RevocationResponse revokeRefreshToken(
            InternalRevocationRequest request, RefreshToken rt) {
        var client = clientStore.find(rt.clientId);
        if (client.isEmpty()) {
            // no client token is useless
            refreshTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (!client.get().isConfidentialClient()) {
            refreshTokenService.revoke(request.token);
            return new RevocationResponse(200, Map.of());
        }

        if (Objects.equals(rt.clientId, request.authenticatedClientId)) {
            refreshTokenService.revoke(request.token);
        }
        return new RevocationResponse(200, Map.of());
    }
}
