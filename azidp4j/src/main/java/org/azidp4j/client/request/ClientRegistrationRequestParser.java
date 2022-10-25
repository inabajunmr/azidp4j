package org.azidp4j.client.request;

import static org.azidp4j.client.request.RequestParser.*;

import java.util.*;

public class ClientRegistrationRequestParser {

    public ClientRegistrationRequest parse(Map<String, Object> parameters) {

        // TODO パラメーター未指定の場合、デフォルト（Set.of)の設定はパーサーじゃなくてドメインでやりたい

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
}
