package org.azidp4j.authorize;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeAudienceMapper;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.accesstoken.InMemoryAccessToken;
import org.azidp4j.token.idtoken.IDTokenIssuer;
import org.azidp4j.util.MapUtil;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;

    private final ClientStore clientStore;

    private final AccessTokenStore accessTokenStore;

    private final ScopeAudienceMapper scopeAudienceMapper;

    private final IDTokenIssuer idTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenStore accessTokenStore,
            ScopeAudienceMapper scopeAudienceMapper,
            IDTokenIssuer idTokenIssuer,
            AzIdPConfig azIdPConfig) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenStore = accessTokenStore;
        this.scopeAudienceMapper = scopeAudienceMapper;
        this.idTokenIssuer = idTokenIssuer;
        this.azIdPConfig = azIdPConfig;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {

        var responseType = ResponseType.parse(authorizationRequest.responseType);
        if (responseType == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_type);
        }

        var responseMode = ResponseMode.of(authorizationRequest.responseMode, responseType);
        if (responseMode == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_response_mode);
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_id_required);
        }
        var clientOpt = clientStore.find(authorizationRequest.clientId);
        if (clientOpt.isEmpty()) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.client_not_found);
        }

        var client = clientOpt.get();

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed);
        }
        URI redirectUri;
        try {
            redirectUri = URI.create(authorizationRequest.redirectUri);
        } catch (IllegalArgumentException e) {
            return AuthorizationResponse.errorPage(
                    AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri);
        }
        if (authorizationRequest.request != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.requestUri != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "request_uri_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.registration != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "registration_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
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
                        responseMode);
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
                        responseMode);
            }
        }

        // validate scope
        if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.codeChallenge == null
                && authorizationRequest.codeChallengeMethod != null) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        ;
        CodeChallengeMethod codeChallengeMethod = null;
        if (authorizationRequest.codeChallengeMethod != null) {
            codeChallengeMethod = CodeChallengeMethod.of(authorizationRequest.codeChallengeMethod);
            if (codeChallengeMethod == null) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_request", "state", authorizationRequest.state),
                        responseMode);
            }
        }

        Set<Prompt> prompt = Prompt.parse(authorizationRequest.prompt);
        if (prompt == null) {
            // prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode);
                }
                if (!authorizationRequest.consentedScope.containsAll(
                        Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                    return AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error",
                                    "consent_required",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
            if (prompt.contains(Prompt.login)) {
                return AuthorizationResponse.additionalPage(Prompt.login, null);
            }
            if (prompt.contains(Prompt.consent)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return AuthorizationResponse.additionalPage(Prompt.login, null);
                } else {
                    return AuthorizationResponse.additionalPage(Prompt.consent, null);
                }
            }
            if (prompt.contains(Prompt.select_account)) {
                return AuthorizationResponse.additionalPage(Prompt.select_account, null);
            }
            if (authorizationRequest.authenticatedUserId == null) {
                return AuthorizationResponse.additionalPage(Prompt.login, null);
            }
            if (!authorizationRequest.consentedScope.containsAll(
                    Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                return AuthorizationResponse.additionalPage(Prompt.consent, null);
            }
        }

        if (!client.responseTypes.containsAll(responseType)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap(
                            "error",
                            "unsupported_response_type",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }

        if (responseType.contains(ResponseType.none)) {
            return AuthorizationResponse.redirect(
                    redirectUri,
                    MapUtil.nullRemovedStringMap("state", authorizationRequest.state),
                    responseMode);
        }

        String accessToken = null;
        String tokenType = null;
        String expiresIn = null;
        String scope = null;
        if (responseType.contains(ResponseType.token)) {
            // issue access token
            var at =
                    new InMemoryAccessToken(
                            UUID.randomUUID().toString(),
                            authorizationRequest.authenticatedUserId,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            scopeAudienceMapper.map(authorizationRequest.scope),
                            Instant.now().getEpochSecond() + azIdPConfig.accessTokenExpirationSec);
            accessTokenStore.save(at);
            accessToken = at.getToken();
            tokenType = "bearer";
            expiresIn = String.valueOf(azIdPConfig.accessTokenExpirationSec);
            scope = authorizationRequest.scope;
        }

        if (scopeValidator.contains(authorizationRequest.scope, "openid")) {
            if (authorizationRequest.maxAge != null) {
                try {
                    var maxAge = Integer.parseInt(authorizationRequest.maxAge);
                    if (Instant.now().getEpochSecond() > authorizationRequest.authTime + maxAge) {
                        if (prompt.contains(Prompt.none)) {
                            return AuthorizationResponse.redirect(
                                    redirectUri,
                                    MapUtil.nullRemovedStringMap(
                                            "error",
                                            "login_required",
                                            "state",
                                            authorizationRequest.state),
                                    responseMode);
                        } else {
                            return AuthorizationResponse.additionalPage(Prompt.login, null);
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
                            responseMode);
                }
            }
        }

        String authorizationCode = null;
        if (responseType.contains(ResponseType.code)) {
            // issue authorization code
            var code =
                    new AuthorizationCode(
                            authorizationRequest.authenticatedUserId,
                            UUID.randomUUID().toString(),
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.redirectUri,
                            authorizationRequest.state,
                            authorizationRequest.authTime,
                            authorizationRequest.nonce,
                            authorizationRequest.codeChallenge,
                            codeChallengeMethod,
                            Instant.now().getEpochSecond()
                                    + azIdPConfig.authorizationCodeExpirationSec);
            authorizationCodeStore.save(code);
            authorizationCode = code.code;
        }

        String idToken = null;
        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(authorizationRequest.scope, "openid")) {
                return AuthorizationResponse.redirect(
                        redirectUri,
                        MapUtil.nullRemovedStringMap(
                                "error", "invalid_scope", "state", authorizationRequest.state),
                        responseMode);
            }
            idToken =
                    idTokenIssuer
                            .issue(
                                    authorizationRequest.authenticatedUserId,
                                    authorizationRequest.clientId,
                                    authorizationRequest.authTime,
                                    authorizationRequest.nonce,
                                    accessToken,
                                    authorizationCode,
                                    client.idTokenSignedResponseAlg)
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
                        scope,
                        "state",
                        authorizationRequest.state),
                responseMode);
    }
}
