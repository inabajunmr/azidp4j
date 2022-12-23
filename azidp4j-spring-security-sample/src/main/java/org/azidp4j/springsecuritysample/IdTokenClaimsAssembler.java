package org.azidp4j.springsecuritysample;

import java.util.HashMap;
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
        var claims = new HashMap<String, Object>();
        if (scopes.contains("profile")) {
            claims.put("name", user.get("name"));
            claims.put("family_name", user.get("family_name"));
            claims.put("given_name", user.get("given_name"));
            claims.put("middle_name", user.get("middle_name"));
            claims.put("nickname", user.get("nickname"));
            claims.put("preferred_username", user.get("preferred_username"));
            claims.put("profile", user.get("profile"));
            claims.put("picture", user.get("picture"));
            claims.put("website", user.get("website"));
            claims.put("gender", user.get("gender"));
            claims.put("birthdate", user.get("birthdate"));
            claims.put("zoneinfo", user.get("zoneinfo"));
            claims.put("locale", user.get("locale"));
        }
        if (scopes.contains("email")) {
            claims.put("email", user.get("email"));
            claims.put("email_verified", user.get("email_verified"));
        }
        if (scopes.contains("address")) {
            claims.put("address", user.get("address"));
        }
        if (scopes.contains("phone")) {
            claims.put("phone_number", user.get("phone_number"));
            claims.put("phone_number_verified", user.get("phone_number_verified"));
        }
        claims.put("updated_at", user.get("updated_at"));
        return claims;
    }
}
