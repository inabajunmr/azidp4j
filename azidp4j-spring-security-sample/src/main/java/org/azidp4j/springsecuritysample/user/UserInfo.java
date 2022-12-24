package org.azidp4j.springsecuritysample.user;

import java.util.HashMap;
import java.util.Set;

public class UserInfo extends HashMap<String, Object> {

    public UserInfo filterByScopes(Set<String> scopes) {
        var filtered = new UserInfo();
        filtered.put("sub", this.get("sub"));
        if (scopes.contains("profile")) {
            filtered.put("name", this.get("name"));
            filtered.put("family_name", this.get("family_name"));
            filtered.put("given_name", this.get("given_name"));
            filtered.put("middle_name", this.get("middle_name"));
            filtered.put("nickname", this.get("nickname"));
            filtered.put("preferred_username", this.get("preferred_username"));
            filtered.put("profile", this.get("profile"));
            filtered.put("picture", this.get("picture"));
            filtered.put("website", this.get("website"));
            filtered.put("gender", this.get("gender"));
            filtered.put("birthdate", this.get("birthdate"));
            filtered.put("zoneinfo", this.get("zoneinfo"));
            filtered.put("locale", this.get("locale"));
        }
        if (scopes.contains("email")) {
            filtered.put("email", this.get("email"));
            filtered.put("email_verified", this.get("email_verified"));
        }
        if (scopes.contains("address")) {
            filtered.put("address", this.get("address"));
        }
        if (scopes.contains("phone")) {
            filtered.put("phone_number", this.get("phone_number"));
            filtered.put("phone_number_verified", this.get("phone_number_verified"));
        }
        filtered.put("updated_at", this.get("updated_at"));
        return filtered;
    }
}
