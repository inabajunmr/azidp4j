package org.azidp4j.introspection;

import java.util.Map;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenStore;
import org.azidp4j.util.MapUtil;

public class Introspect {

    private final AccessTokenService accessTokenService;

    private final RefreshTokenStore refreshTokenStore;

    private final AzIdPConfig config;

    public Introspect(
            AccessTokenService accessTokenService,
            RefreshTokenStore refreshTokenStore,
            AzIdPConfig config) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenStore = refreshTokenStore;
        this.config = config;
    }

    public IntrospectionResponse introspect(InternalIntrospectionRequest request) {
        if (request.token == null) {
            return new IntrospectionResponse(400, Map.of());
        }
        if (request.tokenTypeHint != null && request.tokenTypeHint.equals("refresh_token")) {
            var rtOpt = refreshTokenStore.find(request.token);
            if (rtOpt.isPresent()) {
                return introspectRefreshToken(rtOpt.get());
            }
        }

        var atOpt = accessTokenService.introspect(request.token);
        if (atOpt.isPresent()) {
            return introspectAccessToken(atOpt.get());
        }

        if (request.tokenTypeHint != null && request.tokenTypeHint.equals("refresh_token")) {
            return new IntrospectionResponse(200, Map.of("active", false));
        }

        var rtOpt = refreshTokenStore.find(request.token);
        if (rtOpt.isPresent()) {
            return introspectRefreshToken(rtOpt.get());
        }

        return new IntrospectionResponse(200, Map.of("active", false));
    }

    private IntrospectionResponse introspectAccessToken(AccessToken at) {
        var active = !at.expired();
        if (active) {
            return new IntrospectionResponse(
                    200,
                    MapUtil.nullRemovedMap(
                            "active",
                            true,
                            "scope",
                            at.getScope(),
                            "client_id",
                            at.getClientId(),
                            "token_type",
                            "bearer",
                            "exp",
                            at.getExpiresAtEpochSec(),
                            "iat",
                            at.getIssuedAtEpochSec(),
                            "sub",
                            at.getSub(),
                            "aud",
                            at.getAudience(),
                            "iss",
                            config.issuer));
        } else {
            return new IntrospectionResponse(200, Map.of("active", false));
        }
    }

    private IntrospectionResponse introspectRefreshToken(RefreshToken rt) {
        var active = !rt.expired();
        if (active) {
            return new IntrospectionResponse(
                    200,
                    MapUtil.nullRemovedMap(
                            "active",
                            true,
                            "scope",
                            rt.scope,
                            "client_id",
                            rt.clientId,
                            "token_type",
                            "bearer",
                            "exp",
                            rt.expiresAtEpochSec,
                            "iat",
                            rt.issuedAtEpochSec,
                            "sub",
                            rt.sub,
                            "aud",
                            rt.audience,
                            "iss",
                            config.issuer));
        } else {
            return new IntrospectionResponse(200, Map.of("active", false));
        }
    }
}
