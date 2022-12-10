package org.azidp4j.authorize.request;

import java.util.Set;

public class AuthorizationRequestParser {

    public InternalAuthorizationRequest parse(AuthorizationRequest req) {
        String responseType = req.queryParameters.get("response_type");
        String clientId = req.queryParameters.get("client_id");
        String redirectUri = req.queryParameters.get("redirect_uri");
        String scope = req.queryParameters.get("scope");
        if (scope != null && scope.isEmpty()) {
            scope = null;
        }
        String state = req.queryParameters.get("state");
        String responseMode = req.queryParameters.get("response_mode");
        String nonce = req.queryParameters.get("nonce");
        String maxAge = req.queryParameters.get("max_age");
        String uiLocales = req.queryParameters.get("ui_locales");
        String request = req.queryParameters.get("request");
        String requestUri = req.queryParameters.get("request_uri");
        String registration = req.queryParameters.get("registration");
        String prompt = req.queryParameters.get("prompt");
        String display = req.queryParameters.get("display");
        String codeChallenge = req.queryParameters.get("code_challenge");
        String codeChallengeMethod = req.queryParameters.get("code_challenge_method");

        return InternalAuthorizationRequest.builder()
                .authenticatedUserId(req.authenticatedUserId)
                .consentedScope(req.consentedScope != null ? req.consentedScope : Set.of())
                .authTime(req.authTime)
                .responseType(responseType)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .state(state)
                .responseMode(responseMode)
                .nonce(nonce)
                .maxAge(maxAge)
                .uiLocales(uiLocales)
                .prompt(prompt)
                .display(display)
                .request(request)
                .requestUri(requestUri)
                .registration(registration)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .build();
    }
}
