package org.azidp4j.authorize.request;

import java.util.Arrays;
import java.util.Set;

public class InternalAuthorizationRequest {

    /** Authenticated user identifier (not authorization request parameter) */
    public final String authenticatedUserSubject;
    /** The session's acr value */
    public final String authenticatedUserAcr;

    /** User consented scope (not authorization request parameter) */
    public final Set<String> consentedScope;

    /** Time when the End-User authentication occurred (not authorization request parameter) */
    public final Long authTime;

    /** rfc6749 "authorization code grant", "implicit grant" */
    public final String responseType;

    /** rfc6749 "authorization code grant", "implicit grant" */
    public final String clientId;

    /** rfc6749 "authorization code grant", "implicit grant" */
    public final String redirectUri;

    /** rfc6749 "authorization code grant", "implicit grant" */
    public final String scope;

    /** rfc6749 "authorization code grant", "implicit grant" */
    public final String state;

    /** OAuth 2.0 Multiple Response Type Encoding Practices */
    public final String responseMode;

    /** OpenID Connect Core 1.0 */
    public final String nonce;

    /** OpenID Connect Core 1.0 */
    public final String prompt;

    /** OpenID Connect Core 1.0 */
    public final String display;

    /** OpenID Connect Core 1.0 */
    public final String maxAge;

    /** OpenID Connect Core 1.0 */
    public final String uiLocales;

    /** OpenID Connect Core 1.0 */
    public final String idTokenHint;

    /** OpenID Connect Core 1.0 */
    public final String loginHint;

    /** OpenID Connect Core 1.0 */
    public final String acrValues;

    public final String claims;

    /** OpenID Connect Core 1.0 "6. Passing Request Parameters as JWTs" */
    public final String request;

    /** OpenID Connect Core 1.0 "6. Passing Request Parameters as JWTs" */
    public final String requestUri;

    /**
     * OpenID Connect Core 1.0 "7.2.1. Providing Information with the "registration" Request
     * Parameter"
     */
    public final String registration;

    /** Proof Key for Code Exchange by OAuth Public Clients */
    public final String codeChallenge;

    /** Proof Key for Code Exchange by OAuth Public Clients */
    public final String codeChallengeMethod;

    public static Builder builder() {
        return new Builder();
    }

    public boolean allScopeConsented() {
        if (this.scope == null || this.scope.isEmpty()) {
            return true;
        }

        return this.consentedScope.containsAll(Arrays.stream(this.scope.split(" ")).toList());
    }

    private InternalAuthorizationRequest(
            String authenticatedUserSubject,
            String authenticatedUserAcr,
            Set<String> consentedScope,
            Long authTime,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String responseMode,
            String nonce,
            String maxAge,
            String uiLocales,
            String idTokenHint,
            String loginHint,
            String acrValues,
            String prompt,
            String display,
            String claims,
            String request,
            String requestUri,
            String registration,
            String codeChallenge,
            String codeChallengeMethod) {
        this.authenticatedUserSubject = authenticatedUserSubject;
        this.authenticatedUserAcr = authenticatedUserAcr;
        this.consentedScope = consentedScope;
        this.authTime = authTime;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        this.responseMode = responseMode;
        this.nonce = nonce;
        this.maxAge = maxAge;
        this.idTokenHint = idTokenHint;
        this.loginHint = loginHint;
        this.acrValues = acrValues;
        this.uiLocales = uiLocales;
        this.prompt = prompt;
        this.display = display;
        this.claims = claims;
        this.request = request;
        this.requestUri = requestUri;
        this.registration = registration;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public static class Builder {

        private String authenticatedUserSubject;
        private String authenticatedUserAcr;
        private Set<String> consentedScope;
        private Long authTime;
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String responseMode;
        private String nonce;
        private String maxAge;
        private String idTokenHint;
        private String loginHint;
        private String acrValues;
        private String uiLocales;
        private String prompt;
        private String display;
        private String claims;
        private String request;
        private String requestUri;
        private String registration;
        private String codeChallenge;
        private String codeChallengeMethod;

        private Builder() {}

        public Builder authenticatedUserSubject(String authenticatedUserSubject) {
            this.authenticatedUserSubject = authenticatedUserSubject;
            return this;
        }

        public Builder authenticatedUserAcr(String authenticatedUserAcr) {
            this.authenticatedUserAcr = authenticatedUserAcr;
            return this;
        }

        public Builder consentedScope(Set<String> consentedScope) {
            this.consentedScope = consentedScope;
            return this;
        }

        public Builder authTime(Long authTime) {
            this.authTime = authTime;
            return this;
        }

        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder responseMode(String responseMode) {
            this.responseMode = responseMode;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder maxAge(String maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        public Builder idTokenHint(String idTokenHint) {
            this.idTokenHint = idTokenHint;
            return this;
        }

        public Builder loginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        public Builder acrValues(String acrValues) {
            this.acrValues = acrValues;
            return this;
        }

        public Builder uiLocales(String uiLocales) {
            this.uiLocales = uiLocales;
            return this;
        }

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder display(String display) {
            this.display = display;
            return this;
        }

        public Builder claims(String claims) {
            this.claims = claims;
            return this;
        }

        public Builder request(String request) {
            this.request = request;
            return this;
        }

        public Builder requestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }

        public Builder registration(String registration) {
            this.registration = registration;
            return this;
        }

        public Builder codeChallenge(String codeChallenge) {
            this.codeChallenge = codeChallenge;
            return this;
        }

        public Builder codeChallengeMethod(String codeChallengeMethod) {
            this.codeChallengeMethod = codeChallengeMethod;
            return this;
        }

        public InternalAuthorizationRequest build() {
            return new InternalAuthorizationRequest(
                    authenticatedUserSubject,
                    authenticatedUserAcr,
                    consentedScope,
                    authTime,
                    responseType,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    responseMode,
                    nonce,
                    maxAge,
                    uiLocales,
                    idTokenHint,
                    loginHint,
                    acrValues,
                    prompt,
                    display,
                    claims,
                    request,
                    requestUri,
                    registration,
                    codeChallenge,
                    codeChallengeMethod);
        }
    }
}
