package org.azidp4j.token.refreshtoken;

import java.util.Optional;
import java.util.Set;

/**
 * RefreshTokenService manages refresh token.
 *
 * @see org.azidp4j.token.refreshtoken.inmemory.InMemoryRefreshTokenService as example
 *     implementation
 */
public interface RefreshTokenService {

    /**
     * Issue refresh token.
     *
     * <p>Issued refresh token need to be restored by introspect or consume.
     *
     * @return issued refresh token
     */
    RefreshToken issue(
            String sub,
            String scope,
            String clientId,
            Long exp,
            Long iat,
            Set<String> audience,
            String authorizationCode);

    /**
     * Return issued refresh token.
     *
     * @param token refresh token
     * @return refresh token
     */
    Optional<RefreshToken> introspect(String token);

    /**
     * Consume refresh token.
     *
     * <p>Return persisted refresh token and delete it. If the method doesn't delete refresh token,
     * the token is reusable.
     */
    Optional<RefreshToken> consume(String token);

    /**
     * Invalidate issued refresh token.
     *
     * <p>If the method doesn't override, token revocation doesn't work.
     *
     * @param token refresh token
     */
    default void revoke(String token) {
        // NOP
    }

    /**
     * Invalidate issued refresh token by authorization code.
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
