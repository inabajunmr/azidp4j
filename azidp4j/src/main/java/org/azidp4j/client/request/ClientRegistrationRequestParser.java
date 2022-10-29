package org.azidp4j.client.request;

import static org.azidp4j.client.request.RequestParser.*;

import java.util.*;

public class ClientRegistrationRequestParser {

    public ClientRegistrationRequest parse(Map<String, Object> parameters) {

        var redirectUris = valuesToStringSet(parameters.get("redirect_uris"));
        var grantTypes = valuesToStringSet(parameters.get("grant_types"));
        var responseTypes = valuesToStringSet(parameters.get("response_types"));
        var applicationType = valueToString("application_type", parameters);
        var clientName = valuesToHumanReadable("client_name", parameters);
        var clientUri = valueToString("client_uri", parameters);
        var logoUri = valueToString("logo_uri", parameters);
        var scope = valueToString("scope", parameters);
        var contacts = valuesToStringList(parameters.get("contacts"));
        var tosUri = valuesToHumanReadable("tos_uri", parameters);
        var policyUri = valuesToHumanReadable("policy_uri", parameters);
        var jwksUri = valueToString("jwks_uri", parameters);
        var jwks = valueToString("jwks", parameters);
        var softwareId = valueToString("software_id", parameters);
        var softwareVersion = valueToString("software_version", parameters);
        var tokenEndpointAuthMethod = valueToString("token_endpoint_auth_method", parameters);
        var tokenEndpointAuthSigningAlg =
                valueToString("token_endpoint_auth_signing_alg", parameters);
        var idTokenSignedResponseAlg = valueToString("id_token_signed_response_alg", parameters);
        var defaultMaxAge =
                parameters.containsKey("default_max_age")
                        ? (Long) parameters.get("default_max_age")
                        : null;
        var requireAuthTime =
                parameters.containsKey("default_max_age")
                        ? (Boolean) parameters.get("require_auth_time")
                        : null;
        var initiateLoginUri = valueToString("initiate_login_uri", parameters);
        return ClientRegistrationRequest.builder()
                .redirectUris(redirectUris)
                .grantTypes(grantTypes)
                .responseTypes(responseTypes)
                .applicationType(applicationType)
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
                .tokenEndpointAuthSigningAlg(tokenEndpointAuthSigningAlg)
                .idTokenSignedResponseAlg(idTokenSignedResponseAlg)
                .defaultMaxAge(defaultMaxAge)
                .requireAuthTime(requireAuthTime)
                .initiateLoginUri(initiateLoginUri)
                .build();
    }
}
