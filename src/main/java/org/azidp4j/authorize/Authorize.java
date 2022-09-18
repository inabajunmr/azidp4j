package org.azidp4j.authorize;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.GrantType;
import org.azidp4j.scope.ScopeValidator;
import org.azidp4j.token.accesstoken.AccessTokenIssuer;

public class Authorize {

    private final AuthorizationCodeStore authorizationCodeStore;
    private final ClientStore clientStore;

    private final AccessTokenIssuer accessTokenIssuer;

    private final AzIdPConfig azIdPConfig;

    private final ScopeValidator scopeValidator = new ScopeValidator();

    public Authorize(
            ClientStore clientStore,
            AuthorizationCodeStore authorizationCodeStore,
            AccessTokenIssuer accessTokenIssuer,
            AzIdPConfig azIdPConfig) {
        this.clientStore = clientStore;
        this.authorizationCodeStore = authorizationCodeStore;
        this.accessTokenIssuer = accessTokenIssuer;
        this.azIdPConfig = azIdPConfig;
    }

    public AuthorizationResponse authorize(InternalAuthorizationRequest authorizationRequest) {

        var responseType = ResponseType.of(authorizationRequest.responseType);
        var result = validate(authorizationRequest);
        if (result.hasError) {
            return result.authorizationResponse;
        }
        if (responseType == ResponseType.code) {
            Integer maxAge = null;
            String nonce = null;
            if (scopeValidator.contains(authorizationRequest.scope, "openid")) {
                // OIDC
                if (authorizationRequest.maxAge != null) {
                    maxAge = Integer.parseInt(authorizationRequest.maxAge);
                }
                nonce = authorizationRequest.nonce;
            }

            // issue authorization code
            var code = UUID.randomUUID().toString();
            authorizationCodeStore.save(
                    new AuthorizationCode(
                            authorizationRequest.authenticatedUserId,
                            code,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.state,
                            maxAge,
                            nonce));
            if (authorizationRequest.state == null) {
                return new AuthorizationResponse(302, Map.of("code", code), Map.of());
            } else {
                return new AuthorizationResponse(
                        302, Map.of("code", code, "state", authorizationRequest.state), Map.of());
            }
        } else if (responseType == ResponseType.token) {
            // issue access token
            var accessToken =
                    accessTokenIssuer.issue(
                            authorizationRequest.authenticatedUserId,
                            authorizationRequest.clientId,
                            authorizationRequest.scope);
            return new AuthorizationResponse(
                    302,
                    Map.of(),
                    Map.of(
                            "access_token",
                            accessToken.serialize(),
                            "token_type",
                            "bearer",
                            "expires_in",
                            String.valueOf(azIdPConfig.accessTokenExpirationSec),
                            "scope",
                            authorizationRequest.scope,
                            "state",
                            authorizationRequest.state));
        }
        throw new AssertionError();
    }

    public AuthorizationRequestValidationResult validate(
            InternalAuthorizationRequest authorizationRequest) {
        var responseType = ResponseType.of(authorizationRequest.responseType);
        if (authorizationRequest.responseType == null) {
            return new AuthorizationRequestValidationResult(
                    true, new AuthorizationResponse(400, Map.of(), Map.of()), null);
        }

        // validate client
        if (authorizationRequest.clientId == null) {
            return new AuthorizationRequestValidationResult(
                    true, new AuthorizationResponse(400, Map.of(), Map.of()), null);
        }
        var client = clientStore.find(authorizationRequest.clientId);
        if (client == null) {
            return new AuthorizationRequestValidationResult(
                    true, new AuthorizationResponse(400, Map.of(), Map.of()), null);
        }

        // validate redirect urls
        if (authorizationRequest.redirectUri == null) {
            return new AuthorizationRequestValidationResult(
                    true, new AuthorizationResponse(400, Map.of(), Map.of()), null);
        }
        if (!client.redirectUris.contains(authorizationRequest.redirectUri)) {
            return new AuthorizationRequestValidationResult(
                    true, new AuthorizationResponse(400, Map.of(), Map.of()), null);
        }

        Set<Prompt> prompt = Prompt.parse(authorizationRequest.prompt);
        if (prompt == null) {
            var response =
                    new AuthorizationResponse(
                            302,
                            Map.of("error", "invalid_request", "state", authorizationRequest.state),
                            Map.of());
            return new AuthorizationRequestValidationResult(true, response, null);
        }
        if (prompt.contains(Prompt.none) && prompt.size() != 1) {
            // none with other prompt is invalid
            var response =
                    new AuthorizationResponse(
                            302,
                            Map.of("error", "invalid_request", "state", authorizationRequest.state),
                            Map.of());
            return new AuthorizationRequestValidationResult(true, response, null);
        } else {
            if (prompt.contains(Prompt.login)) {
                return new AuthorizationRequestValidationResult(
                        false, new AuthorizationResponse(AdditionalPage.login), null);
            }
            if (prompt.contains(Prompt.consent)) {
                return new AuthorizationRequestValidationResult(
                        false, new AuthorizationResponse(AdditionalPage.consent), null);
            }
            if (prompt.contains(Prompt.select_account)) {
                return new AuthorizationRequestValidationResult(
                        false, new AuthorizationResponse(AdditionalPage.select_account), null);
            }
            if (authorizationRequest.authenticatedUserId == null) {
                return new AuthorizationRequestValidationResult(
                        false, new AuthorizationResponse(AdditionalPage.login), null);
            }
            if (!authorizationRequest.consentedScope.containsAll(
                    Arrays.stream(authorizationRequest.scope.split(" ")).toList())) {
                return new AuthorizationRequestValidationResult(
                        false, new AuthorizationResponse(AdditionalPage.consent), null);
            }
        }

        if (responseType == ResponseType.code) {
            // validate scope
            if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(
                                        "error",
                                        "invalid_scope",
                                        "state",
                                        authorizationRequest.state),
                                Map.of()),
                        null);
            }

            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.authorization_code)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(
                                        "error",
                                        "unauthorized_client",
                                        "state",
                                        authorizationRequest.state),
                                Map.of()),
                        null);
            }
            if (!client.responseTypes.contains(ResponseType.code)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(
                                        "error",
                                        "unsupported_response_type",
                                        "state",
                                        authorizationRequest.state),
                                Map.of()),
                        null);
            }

            if (scopeValidator.contains(authorizationRequest.scope, "openid")) {
                // OIDC
                if (authorizationRequest.maxAge != null) {
                    try {
                        Integer.parseInt(authorizationRequest.maxAge);
                    } catch (NumberFormatException e) {
                        return new AuthorizationRequestValidationResult(
                                true,
                                new AuthorizationResponse(
                                        302,
                                        Map.of(
                                                "error",
                                                "invalid_request",
                                                "state",
                                                authorizationRequest.state),
                                        Map.of()),
                                null);
                    }
                }
            }

            return new AuthorizationRequestValidationResult(false, null, prompt);
        } else if (responseType == ResponseType.token) {
            if (!scopeValidator.hasEnoughScope(authorizationRequest.scope, client)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(),
                                Map.of(
                                        "error",
                                        "invalid_scope",
                                        "state",
                                        authorizationRequest.state)),
                        null);
            }

            // validate grant type and response type
            if (!client.grantTypes.contains(GrantType.implicit)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(),
                                Map.of(
                                        "error",
                                        "unauthorized_client",
                                        "state",
                                        authorizationRequest.state)),
                        null);
            }
            if (!client.responseTypes.contains(ResponseType.token)) {
                return new AuthorizationRequestValidationResult(
                        true,
                        new AuthorizationResponse(
                                302,
                                Map.of(),
                                Map.of(
                                        "error",
                                        "unsupported_response_type",
                                        "state",
                                        authorizationRequest.state)),
                        null);
            }

            return new AuthorizationRequestValidationResult(false, null, prompt);
        }

        throw new AssertionError();
    }
}
