package org.azidp4j.token.idtoken;

import java.util.Map;
import java.util.Set;

public interface IDTokenClaimsAssembler {

    /**
     * Assemble application-specific claims for ID Token.
     *
     * @param sub user subject
     * @param scopes authorization request's scopes
     * @return custom claims that will be embedded in ID Token
     */
    Map<String, Object> assemble(String sub, Set<String> scopes);
}
