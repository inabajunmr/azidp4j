package org.azidp4j.authorize.authorizationcode;

import org.azidp4j.authorize.request.CodeChallengeMethod;

public class AuthorizationCode {

    /** user identifier */
    public final String sub;

    public final String code;
    public final String scope;
    public final String claims;
    public final String clientId;
    public final String redirectUri;
    public final Long authTime;
    public final String nonce;
    public final String state;
    public final String codeChallenge;
    public final CodeChallengeMethod codeChallengeMethod;
    public final long expiresAtEpochSec;

    public AuthorizationCode(
            String code,
            String sub,
            String scope,
            String claims,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce,
            String codeChallenge,
            CodeChallengeMethod codeChallengeMethod,
            long expiresAtEpochSec) {
        this.code = code;
        this.sub = sub;
        this.scope = scope;
        this.claims = claims;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.authTime = authTime;
        this.nonce = nonce;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAtEpochSec = expiresAtEpochSec;
    }
}
