package org.azidp4j.authorize;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.request.*;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.authorize.response.RedirectTo;
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
        var locales = UILocalesParser.parseUiLocales(authorizationRequest.uiLocales);
        var parsedResponseType =
                ResponseTypeParser.parse(
                        authorizationRequest.responseType,
                        locales,
                        authorizationRequest,
                        config.responseTypeSupported);
        if (parsedResponseType.isError()) {
            return parsedResponseType.getErrorResponse();
        }
        var responseType = parsedResponseType.getValue();

        var parsedResponseMode =
                ResponseModeParser.parse(
                        authorizationRequest.responseMode,
                        responseType,
                        config.responseModesSupported,
                        locales,
                        authorizationRequest);
        if (parsedResponseMode.isError()) {
            return parsedResponseMode.getErrorResponse();
        }
        var responseMode = parsedResponseMode.getValue();

        // validate client
        if (authorizationRequest.clientId == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_id_required,
                    locales,
                    "client_id required",
                    authorizationRequest);
        }
        var clientOpt = clientStore.find(authorizationRequest.clientId);
        if (clientOpt.isEmpty()) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_not_found,
                    locales,
                    "client not found",
                    authorizationRequest);
        }
        var client = clientOpt.get();

        var parsedRedirectURI =
                RedirectURIParser.parse(
                        authorizationRequest.redirectUri, client, locales, authorizationRequest);
        if (parsedRedirectURI.isError()) {
            return parsedRedirectURI.getErrorResponse();
        }
        var redirectUri = parsedRedirectURI.getValue();

        if (authorizationRequest.request != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode,
                    false,
                    "request not supported",
                    authorizationRequest);
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
                    false,
                    "request_uri not supported",
                    authorizationRequest);
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
                    false,
                    "registration not supported",
                    authorizationRequest);
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
                        false,
                        "response_type is code but client doesn't support authorization_code"
                                + " grant_type",
                        authorizationRequest);
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
                        false,
                        "response_type is token or id_token but client doesn't support implicit"
                                + " grant_type",
                        authorizationRequest);
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
                    false,
                    "response_type is id_token but nonce not found",
                    authorizationRequest);
        }

        // validate scope
        if (!scopeValidator.hasEnoughScope(scope, client)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode,
                    false,
                    "client doesn't support enough scope",
                    authorizationRequest);
        }

        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(scope, "openid")) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_scope", "state", authorizationRequest.state),
                        responseMode,
                        false,
                        "authorization request contains id_token response_type but no openid"
                                + " scope",
                        authorizationRequest);
            }
        }

        var parsedCodeChallenge =
                CodeChallengeParser.parse(
                        authorizationRequest.codeChallenge,
                        authorizationRequest.codeChallengeMethod,
                        redirectUri,
                        authorizationRequest.state,
                        responseMode,
                        authorizationRequest);
        if (parsedCodeChallenge.isError()) {
            return parsedCodeChallenge.getErrorResponse();
        }
        var codeChallenge = parsedCodeChallenge.getValue().getCodeChallenge();
        var codeChallengeMethod = parsedCodeChallenge.getValue().getCodeChallengeMethod();

        // parse display
        var parsedDisplay =
                DisplayParser.parse(
                        authorizationRequest.display,
                        redirectUri,
                        responseMode,
                        authorizationRequest);
        if (parsedDisplay.isError()) {
            return parsedDisplay.getErrorResponse();
        }
        var display = parsedDisplay.getValue();

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
                    false,
                    "client doesn't support response_type",
                    authorizationRequest);
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
                        false,
                        "invalid id_token_hint",
                        authorizationRequest);
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
                        false,
                        "id_token_hint subject and authenticatedUser subject unmatched",
                        authorizationRequest);
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
                    false,
                    "prompt parse error",
                    authorizationRequest);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode,
                    false,
                    "prompt contains none and another",
                    authorizationRequest);
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserSubject == null) {
                    // prompt=none but user not authenticated
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode,
                            false,
                            "prompt is none but user not authenticated",
                            authorizationRequest);
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
                            false,
                            "prompt is none but user doesn't consent enough scope",
                            authorizationRequest);
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
                        null,
                        authorizationRequest);
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
                        null,
                        authorizationRequest);
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
                                    false,
                                    "prompt is none but authTime over",
                                    authorizationRequest);
                        } else {
                            return AuthorizationResponse.additionalPage(
                                    Prompt.login,
                                    display,
                                    client.clientId,
                                    scope,
                                    locales,
                                    idTokenHintSub,
                                    authorizationRequest.loginHint,
                                    null,
                                    authorizationRequest);
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
                            false,
                            "max_age is not number",
                            authorizationRequest);
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
                        null,
                        authorizationRequest);
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
                        null,
                        authorizationRequest);
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
                        null,
                        authorizationRequest);
            }
        }

        if (responseType.contains(ResponseType.none)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap("state", authorizationRequest.state),
                    responseMode,
                    true,
                    null,
                    authorizationRequest);
        }

        return AuthorizationResponse.redirect(
                () -> {
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
                                        authorizationRequest.claims,
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
                                        authorizationRequest.claims,
                                        authorizationRequest.clientId,
                                        authorizationRequest.redirectUri,
                                        authorizationRequest.state,
                                        authorizationRequest.authTime,
                                        authorizationRequest.nonce,
                                        codeChallenge,
                                        codeChallengeMethod,
                                        Instant.now().getEpochSecond()
                                                + config.authorizationCodeExpiration.toSeconds());
                        authorizationCode = code.code;
                    }

                    String idToken = null;
                    if (responseType.contains(ResponseType.id_token)) {
                        var accessTokenWillIssued = true;
                        if (accessToken == null & authorizationCode == null) {
                            // https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
                            // The Claims requested by the profile, email, address, and phone scope
                            // values are
                            // returned from the UserInfo Endpoint, as described in Section 5.3.2,
                            // when a
                            // response_type value is used that results in an Access Token being
                            // issued.
                            // However, when no Access Token is issued (which is the case for the
                            // response_type
                            // value id_token), the resulting Claims are returned in the ID Token.
                            accessTokenWillIssued = false;
                        }
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
                                                scope,
                                                authorizationRequest.claims,
                                                accessTokenWillIssued)
                                        .serialize();
                    }
                    return new RedirectTo(
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
                            responseMode);
                },
                true,
                null,
                authorizationRequest);
    }
}
