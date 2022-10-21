package org.azidp4j.scope;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.azidp4j.client.Client;

public class ScopeValidator {

    public boolean hasEnoughScope(String requestedScope, Client client) {
        return hasEnoughScope(requestedScope, client.scope);
    }

    public boolean hasEnoughScope(String requestedScope, String authorizedScope) {
        if (requestedScope == null) {
            return true;
        }
        if (authorizedScope == null) {
            return false;
        }
        var requestedScopes = requestedScope.split(" ");
        var authorizedScopes =
                Arrays.stream(authorizedScope.split(" ")).collect(Collectors.toSet());
        return requestedScopes.length
                == Arrays.stream(requestedScopes).filter(authorizedScopes::contains).count();
    }

    public boolean contains(String requestedScope, String target) {
        if (requestedScope == null) {
            return false;
        }
        var requestedScopes = requestedScope.split(" ");
        return Arrays.stream(requestedScopes).anyMatch(s -> s.equals(target));
    }
}
