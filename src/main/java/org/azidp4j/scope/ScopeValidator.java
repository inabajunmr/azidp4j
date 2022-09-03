package org.azidp4j.scope;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.azidp4j.client.Client;

public class ScopeValidator {

    public boolean hasEnoughScope(String requestedScope, Client client) {
        var requestedScopes = requestedScope.split(" ");
        var clientScopes = Arrays.stream(client.scope.split(" ")).collect(Collectors.toSet());
        return requestedScopes.length
                == Arrays.stream(requestedScopes).filter(s -> clientScopes.contains(s)).count();
    }
}
