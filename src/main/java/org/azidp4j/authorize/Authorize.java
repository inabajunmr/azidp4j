package org.azidp4j.authorize;

import java.time.Instant;
import java.util.*;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;
import org.azidp4j.token.idtoken.IDTokenIssuer;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final ClientStore clientStore;

    private final AccessTokenIssuer accessTokenIssuer;

    private final IDTokenIssuer idTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenIssuer accessTokenIssuer,
            IDTokenIssuer idTokenIssuer,
            AzIdPConfig azIdPConfig) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.idTokenIssuer = idTokenIssuer;
        this.azIdPConfig = azIdPConfig;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {

        var responseType = ResponseType.parse(authorizationRequest.responseType);
        if (responseType == null) {
            return new AuthorizationResponse(400);
        }

        // TODO multiple response type
        // TODO test
        var responseMode = ResponseMode.of(authorizationRequest.responseMode, responseType);
        if (responseMode == null) {
            return new AuthorizationResponse(400);
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return new AuthorizationResponse(400);
        }
        var client = clientStore.find(authorizationRequest.clientId);
        if (client == null) {
            return new AuthorizationResponse(400);
        }

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return new AuthorizationResponse(400);
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return new AuthorizationResponse(400);
        }
        if (authorizationRequest.request != null) {
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap(
                            "error", "request_not_supported", "state", authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.requestUri != null) {
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap(
                            "error",
                            "request_uri_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        if (authorizationRequest.registration != null) {
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap(
                            "error",
                            "registration_not_supported",
                            "state",
                            authorizationRequest.state),
                    responseMode);
        }
        Set<Prompt> prompt = Prompt.parse(authorizationRequest.prompt);
        if (prompt == null) {
            // prompt is invalid
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap("error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap("error", "invalid_request", "state", authorizationRequest.state),
                    responseMode);
        } else {
            if (prompt.contains(Prompt.none)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return new AuthorizationResponse(
                            302,
                            nullRemovedMap(
                                    "error", "login_required", "state", authorizationRequest.state),
                            responseMode);
                }
                if (!authorizationRequest.consentedScope.containsAll(
                        Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                    return new AuthorizationResponse(
                            302,
                            nullRemovedMap(
                                    "error",
                                    "consent_required",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
            if (prompt.contains(Prompt.login)) {
                return new AuthorizationResponse(AdditionalPage.login);
            }
            if (prompt.contains(Prompt.consent)) {
                if (authorizationRequest.authenticatedUserId == null) {
                    return new AuthorizationResponse(AdditionalPage.login);
                } else {
                    return new AuthorizationResponse(AdditionalPage.consent);
                }
            }
            if (prompt.contains(Prompt.select_account)) {
                return new AuthorizationResponse(AdditionalPage.select_account);
            }
            if (authorizationRequest.authenticatedUserId == null) {
                return new AuthorizationResponse(AdditionalPage.login);
            }
            if (!authorizationRequest.consentedScope.containsAll(
                    Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                return new AuthorizationResponse(AdditionalPage.consent);
            }
        }

        if (!client.responseTypes.containsAll(responseType)) {
            return new AuthorizationResponse(
                    302,
                    nullRemovedMap(
                            "error",
                            "unsupported_response_type",
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
                return new AuthorizationResponse(
                        302,
                        nullRemovedMap(
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
                return new AuthorizationResponse(
                        302,
                        nullRemovedMap(
                                "error",
                                "unauthorized_client",
                                "state",
                                authorizationRequest.state),
                        responseMode);
            }
        }

        // validate scope
        if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
            return new AuthorizationResponse(
                    302,
                    Map.of("error", "invalid_scope", "state", authorizationRequest.state),
                    responseMode);
        }

        // TODO prompt=none

        String accessToken = null;
        if (responseType.contains(ResponseType.token)) {
            // issue access token
            accessToken =
                    accessTokenIssuer
                            .issue(
                                    authorizationRequest.authenticatedUserId,
                                    authorizationRequest.clientId,
                                    authorizationRequest.scope)
                            .serialize();
        }

        if (scopeValidator.contains(authorizationRequest.scope, "openid")) {
            if (authorizationRequest.maxAge != null) {
                try {
                    var maxAge = Integer.parseInt(authorizationRequest.maxAge);
                    if (Instant.now().getEpochSecond() + maxAge < authorizationRequest.authTime) {
                        if (prompt.contains(Prompt.none)) {
                            return new AuthorizationResponse(
                                    302,
                                    nullRemovedMap(
                                            "error",
                                            "login_required",
                                            "state",
                                            authorizationRequest.state),
                                    responseMode);
                        } else {
                            return new AuthorizationResponse(AdditionalPage.login);
                        }
                    }
                } catch (NumberFormatException e) {
                    return new AuthorizationResponse(
                            302,
                            nullRemovedMap(
                                    "error",
                                    "invalid_request",
                                    "state",
                                    authorizationRequest.state),
                            responseMode);
                }
            }
        }

        String idToken = null;
        if (responseType.contains(ResponseType.id_token)) {
            // validate scope
            if (!scopeValidator.contains(authorizationRequest.scope, "openid")) {
                return new AuthorizationResponse(
                        302,
                        nullRemovedMap(
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
                                    accessToken)
                            .serialize();
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
                            authorizationRequest.nonce);
            authorizationCodeStore.save(code);
            authorizationCode = code.code;
        }

        return new AuthorizationResponse(
                302,
                nullRemovedMap(
                        "access_token",
                        accessToken,
                        "id_token",
                        idToken,
                        "code",
                        authorizationCode,
                        "token_type",
                        "bearer",
                        "expires_in",
                        String.valueOf(azIdPConfig.accessTokenExpirationSec),
                        "scope",
                        authorizationRequest.scope,
                        "state",
                        authorizationRequest.state),
                responseMode);
    }

    private Map<String, String> nullRemovedMap(String... kv) {
        if (kv.length % 2 != 0) {
            throw new AssertionError();
        }

        var removed = new HashMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) {
            var k = kv[i];
            var v = kv[i + 1];
            if (v != null) {
                removed.put(k, v);
            }
        }
        return removed;
    }
}
