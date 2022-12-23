package org.azidp4j.authorize;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.*;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenValidator;
import org.azidp4j.token.idtoken.InvalidIDTokenException;
import org.azidp4j.util.MapUtil;

public class Authorize {

    private final AuthorizationCodeService authorizationCodeService;

    private final ScopeAudienceMapper scopeAudienceMapper;

    private final ClientStore clientStore;

    private final AccessTokenService accessTokenService;

    private final IDTokenIssuer idTokenIssuer;

    private final IDTokenValidator idTokenValidator;

    private final AzIdPConfig config;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeService authorizationCodeService,
            ScopeAudienceMapper scopeAudienceMapper,
            AccessTokenService accessTokenService,
            IDTokenIssuer idTokenIssuer,
            IDTokenValidator idTokenValidator,
            AzIdPConfig config) {
        this.clientStore = clientStore;
        this.authorizationCodeService = authorizationCodeService;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.accessTokenService = accessTokenService;
        this.idTokenIssuer = idTokenIssuer;
        this.idTokenValidator = idTokenValidator;
        this.config = config;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {
        var scope =
                authorizationRequest.scope != null && !authorizationRequest.scope.isEmpty()
                        ? authorizationRequest.scope
                        : String.join(" ", config.defaultScope);
        if (authorizationRequest.authenticatedUserSubject != null
                && authorizationRequest.authTime == null) {
            throw new AssertionError("When user is authenticated, must set authTime.");
        }
        var locales = parseUiLocales(authorizationRequest.uiLocales);
        Set<ResponseType> responseType;
        try {
            responseType = ResponseType.parse(authorizationRequest.responseType);
        } catch (IllegalArgumentException e) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_type,
                    locales,
                    "response_type parse error");
        }
        if (responseType.isEmpty()) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_type,
                    locales,
                    "response_type parse error");
        }
        if (!config.responseTypeSupported.contains(responseType)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.unsupported_response_type,
                    locales,
                    "azidp doesn't support response_type");
        }

        ResponseMode responseMode;
        try {
            responseMode = ResponseMode.of(authorizationRequest.responseMode, responseType);
        } catch (IllegalArgumentException e) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_mode,
                    locales,
                    "response_mode parse error");
        }
        if (!config.responseModesSupported.contains(responseMode)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.unsupported_response_mode,
                    locales,
                    "azidp doesn't support response_mode");
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_id_required,
                    locales,
                    "client_id required");
        }
        var clientOpt = clientStore.find(authorizationRequest.clientId);
        if (clientOpt.isEmpty()) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_not_found,
                    locales,
                    "client not found");
        }

        var client = clientOpt.get();

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri,
                    locales,
                    "redirect_uri required");
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed,
                    locales,
                    "client doesn't allow redirect_uri");
        }
        URI redirectUri;
        try {
            redirectUri = URI.create(authorizationRequest.redirectUri);
        } catch (IllegalArgumentException e) {
            throw new AssertionError("Client has illegal redirect_uris.", e);
        }
        if (authorizationRequest.request != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode,
                    "request not supported");
        }
        if (authorizationRequest.requestUri != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "request_uri_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode,
                    "request_uri not supported");
        }
        if (authorizationRequest.registration != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "registration_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode,
                    "registration not supported");
        }
        // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
        if (responseType.contains(ResponseType.code)) {
            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.authorization_code)) {
                // if response type has code, need to allowed authorization_code
                // https://www.rfc-editor.org/rfc/rfc7591.html#section-2.1
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state),
                        responseMode,
                        "response_type is code but client doesn't support authorization_code"
                                + " grant_type");
            }
        }

        if (responseType.contains(ResponseType.token)
                || responseType.contains(ResponseType.id_token)) {
            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.implicit)) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state),
                        responseMode,
                        "response_type is token or id_token but client doesn't support implicit"
                                + " grant_type");
            }
        }

        // implicit requires nonce
        // ref. https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
        if (responseType.contains(ResponseType.id_token) && authorizationRequest.nonce == null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode,
                    "response_type is id_token but nonce not found");
        }

        // validate scope
        if (!scopeValidator.hasEnoughScope(scope, client)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode,
                    "client doesn't support enough scope");
        }

        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(scope, "openid")) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_scope", "state", authorizationRequest.state),
                        responseMode,
                        "authorization request contains id_token response_type but no openid"
                                + " scope");
            }
        }

        if (authorizationRequest.codeChallenge == null
                && authorizationRequest.codeChallengeMethod != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode,
                    "code_challenge_method specified but no code_challenge");
        }
        CodeChallengeMethod codeChallengeMethod = null;
        if (authorizationRequest.codeChallengeMethod != null) {
            try {
                codeChallengeMethod =
                        CodeChallengeMethod.of(authorizationRequest.codeChallengeMethod);
            } catch (IllegalArgumentException e) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode,
                        "code_challenge_method parse error");
            }
        } else if (authorizationRequest.codeChallenge != null) {
            codeChallengeMethod = CodeChallengeMethod.S256;
        }

        // parse display
        var display = Display.page;
        if (authorizationRequest.display != null) {
            try {
                display = Display.of(authorizationRequest.display);
            } catch (IllegalArgumentException e) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode,
                        "display parse error");
            }
        }

        // check client supported requested response_type
        if (!client.responseTypes.contains(responseType)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "unsupported_response_type",
                            "state",
                            authorizationRequest.state),
                    responseMode,
                    "client doesn't support response_type");
        }

        // parse id_token_hint
        String idTokenHintSub = null;
        if (authorizationRequest.idTokenHint != null) {
            try {
                var idTokenHint =
                        idTokenValidator.validateForIdTokenHint(
                                authorizationRequest.idTokenHint, client);
                idTokenHintSub = idTokenHint.getPayload().toJSONObject().get("sub").toString();
            } catch (InvalidIDTokenException e) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode,
                        "invalid id_token_hint");
            }
        }

        // check authenticated user subject and id_token_hint sub are same.
        if (idTokenHintSub != null && authorizationRequest.authenticatedUserSubject != null) {
            if (!Objects.equals(idTokenHintSub, authorizationRequest.authenticatedUserSubject)) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "login_required", "state", authorizationRequest.state),
                        responseMode,
                        "id_token_hint subject and authenticatedUser subject unmatched");
            }
        }

        // parse prompt
        Set<Prompt> prompt;
        try {
            prompt = Prompt.parse(authorizationRequest.prompt);
        } catch (IllegalArgumentException e) {
            // prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode,
                    "prompt parse error");
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode,
                    "prompt contains none and another");
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserSubject == null) {
                    // prompt=none but user not authenticated
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode,
                            "prompt is none but user not authenticated");
                }
                if (!authorizationRequest.allScopeConsented()) {
                    // prompt=none but user doesn't consent enough scopes.
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "consent_required",
                                    "state",
                                    authorizationRequest.state),
                            responseMode,
                            "prompt is none but user doesn't consent enough scope");
                }
            }
            if (prompt.contains(Prompt.login)) {
                return AuthorizationResponse.additionalPage(
                        Prompt.login,
                        display,
                        client.clientId,
                        scope,
                        locales,
                        idTokenHintSub,
                        authorizationRequest.loginHint,
                        null);
            }
            if (authorizationRequest.authenticatedUserSubject == null) {
                return AuthorizationResponse.additionalPage(
                        Prompt.login,
                        display,
                        client.clientId,
                        scope,
                        locales,
                        idTokenHintSub,
                        authorizationRequest.loginHint,
                        null);
            }
            if (authorizationRequest.maxAge != null || client.defaultMaxAge != null) {
                try {
                    var maxAge =
                            authorizationRequest.maxAge != null
                                    ? Long.parseLong(authorizationRequest.maxAge)
                                    : client.defaultMaxAge;
                    if (Instant.now().getEpochSecond() > authorizationRequest.authTime + maxAge) {
                        if (prompt.contains(Prompt.none)) {
                            return AuthorizationResponse.redirect(
                                    redirectUri,
                                    MapUtil.nullRemovedStringMap(
                                            "error",
                                            "login_required",
                                            "state",
                                            authorizationRequest.state),
                                    responseMode,
                                    "prompt is none but authTime over");
                        } else {
                            return AuthorizationResponse.additionalPage(
                                    Prompt.login,
                                    display,
                                    client.clientId,
                                    scope,
                                    locales,
                                    idTokenHintSub,
                                    authorizationRequest.loginHint,
                                    null);
                        }
                    }
                } catch (NumberFormatException e) {
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "invalid_request",
                                    "state",
                                    authorizationRequest.state),
                            responseMode,
                            "max_age is not number");
                }
            }
            if (prompt.contains(Prompt.consent)) {
                return AuthorizationResponse.additionalPage(
                        Prompt.consent,
                        display,
                        client.clientId,
                        scope,
                        locales,
                        idTokenHintSub,
                        authorizationRequest.loginHint,
                        null);
            }
            if (prompt.contains(Prompt.select_account)) {
                return AuthorizationResponse.additionalPage(
                        Prompt.select_account,
                        display,
                        client.clientId,
                        scope,
                        locales,
                        idTokenHintSub,
                        authorizationRequest.loginHint,
                        null);
            }
            if (!authorizationRequest.allScopeConsented()) {
                return AuthorizationResponse.additionalPage(
                        Prompt.consent,
                        display,
                        client.clientId,
                        scope,
                        locales,
                        idTokenHintSub,
                        authorizationRequest.loginHint,
                        null);
            }
        }

        if (responseType.contains(ResponseType.none)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap("state", authorizationRequest.state),
                    responseMode,
                    null);
        }

        String accessToken = null;
        String tokenType = null;
        String expiresIn = null;
        String responseScope = null;
        if (responseType.contains(ResponseType.token)) {
            responseScope = scope;
            // issue access token
            var at =
                    accessTokenService.issue(
                            authorizationRequest.authenticatedUserSubject,
                            scope,
                            authorizationRequest.clientId,
                            Instant.now().getEpochSecond()
                                    + config.accessTokenExpiration.toSeconds(),
                            Instant.now().getEpochSecond(),
                            scopeAudienceMapper.map(scope),
                            null);
            accessToken = at.token;
            tokenType = "bearer";
            expiresIn = String.valueOf(config.accessTokenExpiration.getSeconds());
        }

        String authorizationCode = null;
        if (responseType.contains(ResponseType.code)) {
            // issue authorization code
            var code =
                    authorizationCodeService.issue(
                            authorizationRequest.authenticatedUserSubject,
                            scope,
                            authorizationRequest.clientId,
                            authorizationRequest.redirectUri,
                            authorizationRequest.state,
                            authorizationRequest.authTime,
                            authorizationRequest.nonce,
                            authorizationRequest.codeChallenge,
                            codeChallengeMethod,
                            Instant.now().getEpochSecond()
                                    + config.authorizationCodeExpiration.toSeconds());
            authorizationCode = code.code;
        }

        String idToken = null;
        if (responseType.contains(ResponseType.id_token)) {
            idToken =
                    idTokenIssuer
                            .issue(
                                    authorizationRequest.authenticatedUserSubject,
                                    authorizationRequest.clientId,
                                    authorizationRequest.authTime,
                                    authorizationRequest.nonce,
                                    accessToken,
                                    authorizationCode,
                                    client.idTokenSignedResponseAlg,
                                    scope)
                            .serialize();
        }

        return AuthorizationResponse.redirect(
                redirectUri,
                MapUtil.nullRemovedStringMap(
                        "access_token",
                        accessToken,
                        "id_token",
                        idToken,
                        "code",
                        authorizationCode,
                        "token_type",
                        tokenType,
                        "expires_in",
                        expiresIn,
                        "scope",
                        responseScope,
                        "state",
                        authorizationRequest.state),
                responseMode,
                null);
    }

    private List<String> parseUiLocales(String uiLocales) {
        if (uiLocales == null) {
            return List.of();
        }

        return Arrays.stream(uiLocales.replaceAll(" +", " ").split(" ")).toList();
    }
}
