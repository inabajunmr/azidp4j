package org.azidp4j.authorize.authorizationcode;

import java.util.Optional;
import org.azidp4j.authorize.request.CodeChallengeMethod;

public interface AuthorizationCodeService {

    AuthorizationCode issue(
            String sub,
            String scope,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce,
            String codeChallenge,
            CodeChallengeMethod codeChallengeMethod,
            Long exp);

    Optional<AuthorizationCode> consume(String code);
}
