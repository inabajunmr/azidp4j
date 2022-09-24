package org.azidp4j.springsecuritysample.consent;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class InMemoryUserConsentStore {

    // Map<username, Map<client_id,Set<scope>>>
    private final Map<String, Map<String, Set<String>>> userConsentMap = new HashMap<>();

    public void consent(String username, String clientId, Set<String> scopes) {
        // TODO scopes need to be modifiable
        if (userConsentMap.containsKey(username)
                && userConsentMap.get(username).containsKey(clientId)) {
            userConsentMap.get(username).get(clientId).addAll(scopes);
            return;
        }

        if (userConsentMap.containsKey(username)) {
            userConsentMap.get(username).put(clientId, scopes);
            return;
        }
        var clientIdScopesMap = new HashMap<String, Set<String>>();
        clientIdScopesMap.put(clientId, scopes);
        userConsentMap.put(username, clientIdScopesMap);
    }

    public Set<String> getUserConsents(String username, String clientId) {
        return userConsentMap.getOrDefault(username, Map.of()).getOrDefault(clientId, Set.of());
    }
}
