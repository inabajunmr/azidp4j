package org.azidp4j.springsecuritysample;

import java.util.Map;
import java.util.Set;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.azidp4j.token.idtoken.IDTokenClaimsAssembler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class IdTokenClaimsAssembler implements IDTokenClaimsAssembler {

    @Autowired UserStore userStore;

    /** https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims */
    @Override
    public Map<String, Object> assemble(String sub, Set<String> scopes) {
        var user = userStore.find(sub);
        return user.filterByScopes(scopes);
    }
}
