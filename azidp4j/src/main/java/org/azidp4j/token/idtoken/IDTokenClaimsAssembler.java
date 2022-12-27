package org.azidp4j.token.idtoken;

import java.util.Map;
import java.util.Set;

public interface IDTokenClaimsAssembler {

    /**
     * Assemble application-specific claims for ID Token.
     *
     * <p>Specification said `The Claims requested by the profile, email, address, and phone scope
     * values are returned from the UserInfo Endpoint, as described in Section 5.3.2, when a
     * response_type value is used that results in an Access Token being issued. However, when no
     * Access Token is issued (which is the case for the response_type value id_token), the
     * resulting Claims are returned in the ID Token.`
     *
     * <p>So IDTokenClaimsAssembler implemented class should ignores scopes parameter when
     * accessTokenWillBeIssued is true.
     *
     * <p>see. https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims and
     * https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
     *
     * @param sub user subject
     * @param accessTokenWillBeIssued the series of request causes issuing Access Token
     * @param scopes authorization request's scopes
     * @param claims authorization request's claims parameter
     * @return custom claims that will be embedded in ID Token
     */
    Map<String, Object> assemble(
            String sub, boolean accessTokenWillBeIssued, Set<String> scopes, String claims);
}
