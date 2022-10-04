package org.azidp4j.client;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientConfigurationRequestParser {

    public ClientConfigurationRequest parse(String clientId, Map<String, Object> parameters) {
        var redirectUris =
                parameters.containsKey("redirect_uris")
                        ? valuesToStringSet(parameters.get("redirect_uris"))
                        : null;
        var grantTypes =
                parameters.containsKey("grant_types")
                        ? valuesToStringSet(parameters.get("grant_types"))
                        : null;
        var responseTypes =
                parameters.containsKey("response_types")
                        ? valuesToStringSet(parameters.get("response_types"))
                        : null;
        var scope = parameters.containsKey("scope") ? parameters.get("scope").toString() : null;
        var tokenEndpointAuthMethod =
                parameters.containsKey("token_endpoint_auth_method")
                        ? parameters.get("token_endpoint_auth_method").toString()
                        : null;
        var idTokenSignedResponseAlg =
                parameters.containsKey("id_token_signed_response_alg")
                        ? valuesToStringSet(parameters.get("id_token_signed_response_alg"))
                        : null;
        return ClientConfigurationRequest.builder()
                .clientId(clientId)
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .responseTypes(responseTypes)
                .scope(scope)
                .tokenEndpointAuthMethod(tokenEndpointAuthMethod)
                .idTokenSignedResponseAlg(idTokenSignedResponseAlg)
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
