package org.azidp4j.token.accesstoken;

import java.util.Optional;
import java.util.Set;

/**
 * AccessTokenService manages access token.
 *
 * @see org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService as example implementation
 */
public interface AccessTokenService {

    /**
     * Issue access token.
     *
     * <p>Issued access token need to be restored by introspect.
     *
     * @return issued access token
     */
    AccessToken issue(
            String sub,
            String scope,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode);

    /**
     * Return issued access token.
     *
     * @param token access token
     * @return access token
     */
    Optional<AccessToken> introspect(String token);

    /**
     * Invalidate issued access token.
     *
     * <p>If the method doesn't override, token revocation doesn't work.
     *
     * @param token access token
     */
    default void revoke(String token) {
        // NOP
    }

    /**
     * Invalidate issued access token by authorization code.
     *
     * <p>If the method doesn't override, reusing authorization code doesn't cause issued token
     * revocation.
     *
     * @param authorizationCode authorization code
     */
    default void revokeByAuthorizationCode(String authorizationCode) {
        // NOP
    }
}
