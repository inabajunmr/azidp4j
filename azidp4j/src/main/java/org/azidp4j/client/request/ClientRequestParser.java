package org.azidp4j.client.request;

import static org.azidp4j.RequestParserUtil.*;

public class ClientRequestParser {

    public InternalClientRequest parse(ClientRequest request) {
        var parameters = request.bodyParameters;
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
        var jwks = valueToJwks("jwks", parameters);
        var softwareId = valueToString("software_id", parameters);
        var softwareVersion = valueToString("software_version", parameters);
        var tokenEndpointAuthMethod = valueToString("token_endpoint_auth_method", parameters);
        var tokenEndpointAuthSigningAlg =
                valueToString("token_endpoint_auth_signing_alg", parameters);
        var introspectionEndpointAuthMethod =
                valueToString("introspection_endpoint_auth_method", parameters);
        var introspectionEndpointAuthSigningAlg =
                valueToString("introspection_endpoint_auth_signing_alg", parameters);
        var revocationEndpointAuthMethod =
                valueToString("revocation_endpoint_auth_method", parameters);
        var revocationEndpointAuthSigningAlg =
                valueToString("revocation_endpoint_auth_signing_alg", parameters);

        var idTokenSignedResponseAlg = valueToString("id_token_signed_response_alg", parameters);
        var defaultMaxAge =
                parameters.containsKey("default_max_age")
                        ? (Long) parameters.get("default_max_age")
                        : null;
        var requireAuthTime =
                parameters.containsKey("default_max_age")
                        ? (Boolean) parameters.get("require_auth_time")
                        : null;
        var defaultAcrValues = valuesToStringList(parameters.get("default_acr_values"));
        var initiateLoginUri = valueToString("initiate_login_uri", parameters);
        return InternalClientRequest.builder()
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
                .introspectionEndpointAuthMethod(introspectionEndpointAuthMethod)
                .introspectionEndpointAuthSigningAlg(introspectionEndpointAuthSigningAlg)
                .revocationEndpointAuthMethod(revocationEndpointAuthMethod)
                .revocationEndpointAuthSigningAlg(revocationEndpointAuthSigningAlg)
                .idTokenSignedResponseAlg(idTokenSignedResponseAlg)
                .defaultMaxAge(defaultMaxAge)
                .requireAuthTime(requireAuthTime)
                .defaultAcrValues(defaultAcrValues)
                .initiateLoginUri(initiateLoginUri)
                .build();
    }
}
