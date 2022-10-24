package org.azidp4j.client.request;

import java.util.*;
import java.util.stream.Collectors;
import org.azidp4j.util.HumanReadable;

public class ClientRegistrationRequestParser {

    public ClientRegistrationRequest parse(Map<String, Object> parameters) {
        var redirectUris = valuesToStringSet(parameters.getOrDefault("redirect_uris", Set.of()));
        var grantTypes = valuesToStringSet(parameters.getOrDefault("grant_types", Set.of()));
        var responseTypes = valuesToStringSet(parameters.getOrDefault("response_types", Set.of()));
        var clientName = valuesToHumanReadable("client_name", parameters);
        var clientUri = valueToString("client_uri", parameters);
        var logoUri = valueToString("logo_uri", parameters);
        var scope = valueToString("scope", parameters);
        var contacts = valuesToStringList(parameters.getOrDefault("contacts", List.of()));
        var tosUri = valuesToHumanReadable("tos_uri", parameters);
        var policyUri = valuesToHumanReadable("policy_uri", parameters);
        var jwksUri = valueToString("jwks_uri", parameters);
        var jwks = valueToString("jwks", parameters);
        var softwareId = valueToString("software_id", parameters);
        var softwareVersion = valueToString("software_version", parameters);
        var tokenEndpointAuthMethod = valueToString("token_endpoint_auth_method", parameters);
        var idTokenSignedResponseAlg = valueToString("id_token_signed_response_alg", parameters);
        return ClientRegistrationRequest.builder()
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .responseTypes(responseTypes)
                .clientName(clientName)
                .clientUri(clientUri)
                .logoUri(logoUri)
                .scope(scope)
                .contacts(contacts)
                .tosUri(tosUri)
                .policyUri(policyUri)
                .jwksUri(jwksUri)
                .jwks(jwks)
                .softwareId(softwareId)
                .softwareVersion(softwareVersion)
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

    private List<String> valuesToStringList(Object values) {
        if (values instanceof Collection) {
            var onlyString =
                    ((Collection<?>) values)
                            .stream().filter(v -> v instanceof String).collect(Collectors.toList());
            return ((List<String>) onlyString);
        } else if (values instanceof String[]) {
            return Arrays.stream((String[]) values).collect(Collectors.toList());
        }
        return List.of();
    }

    private HumanReadable<String> valuesToHumanReadable(
            String key, Map<String, Object> parameters) {
        var clientName = (String) parameters.get(key);
        var map = new HashMap<String, String>();
        parameters.keySet().stream()
                .filter(k -> k.startsWith("client_name#"))
                .forEach(
                        k -> {
                            map.put(k.substring(k.indexOf('#')), (String) parameters.get(k));
                        });
        return new HumanReadable<String>("client_name", clientName, map);
    }

    private String valueToString(String key, Map<String, Object> parameters) {
        return parameters.containsKey(key) ? parameters.get(key).toString() : null;
    }
}
