package org.azidp4j.authorize.parser;

import java.net.URI;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.util.MapUtil;

/** Authorization Request Parser for code_challenge and code_challenge_method */
public class CodeChallengeParser {

    public static ParseResult<CodeChallenge> parse(
            String codeChallenge,
            String codeChallengeMethod,
            URI redirectUri,
            String state,
            ResponseMode responseMode,
            InternalAuthorizationRequest authorizationRequest) {

        if (codeChallenge == null && codeChallengeMethod != null) {
            return ParseResult.error(
                    AuthorizationResponse.redirect(
                            redirectUri,
                            MapUtil.nullRemovedStringMap(
                                    "error", "invalid_request", "state", state),
                            responseMode,
                            false,
                            "code_challenge_method specified but no code_challenge",
                            authorizationRequest));
        }
        CodeChallengeMethod codeChallengeMethodTemp = null;
        if (codeChallengeMethod != null) {
            try {
                codeChallengeMethodTemp = CodeChallengeMethod.of(codeChallengeMethod);
            } catch (IllegalArgumentException e) {
                return ParseResult.error(
                        AuthorizationResponse.redirect(
                                redirectUri,
                                MapUtil.nullRemovedStringMap(
                                        "error", "invalid_request", "state", state),
                                responseMode,
                                false,
                                "code_challenge_method parse error",
                                authorizationRequest));
            }
        } else if (codeChallenge != null) {
            codeChallengeMethodTemp = CodeChallengeMethod.S256;
        }

        return ParseResult.of(new CodeChallenge(codeChallengeMethodTemp, codeChallenge));
    }
}
