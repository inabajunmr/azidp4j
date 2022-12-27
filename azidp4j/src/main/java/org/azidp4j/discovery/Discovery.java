package org.azidp4j.discovery;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.request.CodeChallengeMethod;
import org.azidp4j.util.MapUtil;

public class Discovery {

    private final AzIdPConfig config;

    private final DiscoveryConfig discoveryConfig;

    public Discovery(AzIdPConfig config, DiscoveryConfig discoveryConfig) {
        this.config = config;
        this.discoveryConfig = discoveryConfig;
    }

    public Map<String, Object> metadata() {
        if (discoveryConfig == null) {
            throw new AssertionError("Requires DiscoveryConfig for init AzIdp.");
        }
        return MapUtil.nullRemovedMap(
                "issuer",
                config.issuer,
                "authorization_endpoint",
                discoveryConfig.authorizationEndpoint,
                "token_endpoint",
                discoveryConfig.tokenEndpoint,
                "userinfo_endpoint",
                discoveryConfig.userInfoEndpoint,
                "jwks_uri",
                discoveryConfig.jwksEndpoint,
                "registration_endpoint",
                discoveryConfig.clientRegistrationEndpoint,
                "revocation_endpoint",
                discoveryConfig.revocationEndpoint,
                "introspection_endpoint",
                discoveryConfig.introspectionEndpoint,
                "scopes_supported",
                config.scopesSupported,
                "response_types_supported",
                config.responseTypeSupported.stream()
                        .map(r -> r.stream().map(Enum::name).collect(Collectors.toSet()))
                        .map(r -> String.join(" ", r.toArray(new String[0])))
                        .collect(Collectors.toSet()),
                "response_modes_supported",
                config.responseModesSupported,
                "grant_types_supported",
                config.grantTypesSupported,
                "acr_values_supported",
                null,
                "subject_types_supported",
                Set.of("public"),
                "id_token_signing_alg_values_supported",
                config.idTokenSigningAlgValuesSupported,
                "id_token_encryption_alg_values_supported",
                Set.of(),
                "id_token_encryption_enc_values_supported",
                Set.of(),
                "userinfo_signing_alg_values_supported",
                discoveryConfig.userinfoSigningAlgValuesSupported,
                "userinfo_encryption_alg_values_supported",
                discoveryConfig.userinfoEncryptionAlgValuesSupported,
                "userinfo_encryption_enc_values_supported",
                discoveryConfig.userinfoEncryptionEncValuesSupported,
                "request_object_signing_alg_values_supported",
                null,
                "request_object_encryption_alg_values_supported",
                null,
                "request_object_encryption_enc_values_supported",
                null,
                "token_endpoint_auth_methods_supported",
                config.tokenEndpointAuthMethodsSupported,
                "token_endpoint_auth_signing_alg_values_supported",
                config.tokenEndpointAuthSigningAlgValuesSupported,
                "introspection_endpoint_auth_methods_supported",
                config.introspectionEndpointAuthMethodsSupported,
                "introspection_endpoint_auth_signing_alg_values_supported",
                config.introspectionEndpointAuthSigningAlgValuesSupported,
                "revocation_endpoint_auth_methods_supported",
                config.revocationEndpointAuthMethodsSupported,
                "revocation_endpoint_auth_signing_alg_values_supported",
                config.revocationEndpointAuthSigningAlgValuesSupported,
                "display_values_supported",
                discoveryConfig.displayValueSupported,
                "claim_types_supported",
                "normal",
                "claims_supported",
                discoveryConfig.claimsSupported,
                "service_documentation",
                discoveryConfig.serviceDocumentation,
                "claims_locales_supported",
                null,
                "ui_locales_supported",
                discoveryConfig.uiLocalesSupported,
                "claims_parameter_supported",
                discoveryConfig.claimsParameterSupported,
                "request_parameter_supported",
                false,
                // "request_uri_parameter_supported", // the parameter is false,
                // oidcc-basic-certification-test-plan	will be failed.
                // false,
                "require_request_uri_registration",
                false,
                "op_policy_uri",
                discoveryConfig.opPolicyUri,
                "op_tos_uri",
                discoveryConfig.opTosUri,
                "code_challenge_methods_supported",
                Set.of(CodeChallengeMethod.PLAIN.name(), CodeChallengeMethod.S256.name()));
    }
}
