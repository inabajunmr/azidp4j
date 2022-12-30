package org.azidp4j.authorize.authorizationcode;

import java.util.Optional;
import org.azidp4j.authorize.request.CodeChallengeMethod;

/**
 * AuthorizationCodeService manages authorization code.
 *
 * @see org.azidp4j.authorize.authorizationcode.inmemory.InMemoryAuthorizationCodeService as example
 *     implementation
 */
public interface AuthorizationCodeService {

    /**
     * Issue authorization code.
     *
     * <p>Issued authorization code need to be restored by consume.
     *
     * @return issued authorization code
     */
    AuthorizationCode issue(
            String sub,
            String acr,
            String scope,
            String claims,
            String clientId,
            String redirectUri,
            String state,
            Long authTime,
            String nonce,
            String codeChallenge,
            CodeChallengeMethod codeChallengeMethod,
            Long exp);

    /**
     * Consume authorization code.
     *
     * <p>Return persisted authorization code and delete it. If the method doesn't delete
     * authorization code, the code is reusable.
     */
    Optional<AuthorizationCode> consume(String code);
}
