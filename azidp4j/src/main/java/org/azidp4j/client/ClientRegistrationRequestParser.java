package org.azidp4j.client;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientRegistrationRequestParser {

    public ClientRegistrationRequest parse(Map<String, Object> parameters) {
        var redirectUris = valuesToStringSet(parameters.getOrDefault("redirect_uris", Set.of()));
        var grantTypes = valuesToStringSet(parameters.getOrDefault("grant_types", Set.of()));
        var responseTypes = valuesToStringSet(parameters.getOrDefault("response_types", Set.of()));
        var scope = parameters.getOrDefault("scope", "").toString();
        var tokenEndpointAuthMethod =
                parameters.getOrDefault("token_endpoint_auth_method", "").toString();
        return ClientRegistrationRequest.builder()
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .responseTypes(responseTypes)
                .scope(scope)
                .tokenEndpointAuthMethod(tokenEndpointAuthMethod)
                .build();
    }

    private Set<String> valuesToStringSet(Object values) {
        if (values instanceof Collection) {
            var onlyString =
                    ((Collection<?>) values)
                            .stream().filter(v -> v instanceof String).collect(Collectors.toSet());
            return ((Set<String>) onlyString);
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toSet());
        }
        return Set.of();
    }
}
