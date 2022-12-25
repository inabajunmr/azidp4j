package org.azidp4j.springsecuritysample.user;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Set;

public class UserInfo extends HashMap<String, Object> {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public UserInfo filterForIDToken(
            boolean accessTokenWillBeIssued, Set<String> scopes, String claims) {
        var filteredByClaims = filterByClaims(claims, ClaimsType.id_token);
        var filteredByScope = new UserInfo();
        if (!accessTokenWillBeIssued) {
            filteredByScope = filterByScope(scopes);
        }
        filteredByScope.putAll(filteredByClaims);
        return filteredByScope;
    }

    public UserInfo filterForUserInfoEndpoint(Set<String> scopes, String claims) {
        var filteredByClaims = filterByClaims(claims, ClaimsType.userinfo);
        var filteredByScope = filterByScope(scopes);
        filteredByScope.putAll(filteredByClaims);
        return filteredByScope;
    }

    private UserInfo filterByScope(Set<String> scopes) {
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

    private UserInfo filterByClaims(String claims, ClaimsType claimsType) {
        var filteredByClaims = new UserInfo();
        if (claims != null) {
            try {
                var tree = MAPPER.readTree(claims);
                if (tree.has(claimsType.name())) {
                    var idTokenNode = tree.get(claimsType.name());
                    if (idTokenNode.isObject()) {
                        idTokenNode
                                .fieldNames()
                                .forEachRemaining(
                                        k -> {
                                            var target = idTokenNode.get(k);
                                            if (target.isNull() && this.containsKey(k)) {
                                                filteredByClaims.put(k, this.get(k));
                                                return;
                                            }
                                            if (target.has("essential") && this.containsKey(k)) {
                                                filteredByClaims.put(k, this.get(k));
                                                return;
                                            }
                                            if (target.has("value")
                                                    && target.get("value").isValueNode()
                                                    && this.containsKey(k)
                                                    && target.get("value").equals(this.get(k))) {
                                                filteredByClaims.put(k, this.get(k));
                                                return;
                                            }
                                            if (target.has("values")
                                                    && target.get("values").isArray()
                                                    && this.containsKey(k)) {
                                                for (JsonNode value : target.get("values")) {
                                                    if (this.get(k) instanceof String v
                                                            && value.textValue().equals(v)) {
                                                        filteredByClaims.put(k, this.get(k));
                                                        return;
                                                    }
                                                    if (this.get(k) instanceof Boolean v
                                                            && value.booleanValue() == v) {
                                                        filteredByClaims.put(k, this.get(k));
                                                        return;
                                                    }
                                                    if (this.get(k) instanceof Number v
                                                            && value.numberValue().equals(v)) {
                                                        filteredByClaims.put(k, this.get(k));
                                                        return;
                                                    }
                                                }
                                            }
                                        });
                    }
                }
            } catch (JsonProcessingException e) {
                // NOP
            }
        }
        return filteredByClaims;
    }
}

enum ClaimsType {
    id_token,
    userinfo
}
