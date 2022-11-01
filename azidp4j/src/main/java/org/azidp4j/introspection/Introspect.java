package org.azidp4j.introspection;

import java.util.Map;
import java.util.Objects;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.introspection.request.InternalIntrospectionRequest;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.introspection.request.IntrospectionRequestParser;
import org.azidp4j.introspection.response.IntrospectionResponse;
import org.azidp4j.revocation.request.TokenTypeHint;
import org.azidp4j.token.accesstoken.AccessToken;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshToken;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.util.MapUtil;

public class Introspect {

    private final AccessTokenService accessTokenService;

    private final RefreshTokenService refreshTokenService;

    private final AzIdPConfig config;

    private final IntrospectionRequestParser introspectionRequestParser =
            new IntrospectionRequestParser();

    public Introspect(
            AccessTokenService accessTokenService,
            RefreshTokenService refreshTokenService,
            AzIdPConfig config) {
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.config = config;
    }

    public IntrospectionResponse introspect(IntrospectionRequest request) {
        InternalIntrospectionRequest req;
        try {
            req = introspectionRequestParser.parse(request);
        } catch (IllegalArgumentException e) {
            return new IntrospectionResponse(400, Map.of());
        }
        if (req.token == null) {
            return new IntrospectionResponse(400, Map.of());
        }
        var hint = TokenTypeHint.of(req.tokenTypeHint);
        if (hint == null) {
            hint = TokenTypeHint.access_token;
        }

        if (Objects.equals(hint, TokenTypeHint.refresh_token)) {
            var rtOpt = refreshTokenService.introspect(req.token);
            if (rtOpt.isPresent()) {
                return introspectRefreshToken(rtOpt.get());
            }
        }

        var atOpt = accessTokenService.introspect(req.token);
        if (atOpt.isPresent()) {
            return introspectAccessToken(atOpt.get());
        }

        if (Objects.equals(hint, TokenTypeHint.refresh_token)) {
            return new IntrospectionResponse(200, Map.of("active", false));
        }

        var rtOpt = refreshTokenService.introspect(req.token);
        return rtOpt.map(this::introspectRefreshToken)
                .orElseGet(() -> new IntrospectionResponse(200, Map.of("active", false)));
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
