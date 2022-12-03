package org.azidp4j.discovery;

import java.util.Map;
import java.util.Set;
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
                "scopes_supported",
                config.scopesSupported,
                "response_types_supported",
                config.responseTypeSupported,
                "response_modes_supported",
                config.responseModesSupported,
                "grant_types_supported",
                config.grantTypesSupported,
                // "acr_values_supported", null,
                "subject_types_supported",
                Set.of("public"),
                "id_token_signing_alg_values_supported",
                config.idTokenSigningAlgValuesSupported,
                "id_token_encryption_alg_values_supported",
                Set.of(),
                "id_token_encryption_enc_values_supported",
                Set.of(),
                "userinfo_signing_alg_values_supported",
                Set.of(), // TODO
                "userinfo_encryption_alg_values_supported",
                Set.of(), // TODO
                "userinfo_encryption_enc_values_supported",
                Set.of(), // TODO
                "request_object_signing_alg_values_supported",
                Set.of(),
                "request_object_encryption_alg_values_supported",
                Set.of(),
                "request_object_encryption_enc_values_supported",
                Set.of(),
                "token_endpoint_auth_methods_supported",
                Set.of(
                        "client_secret_basic",
                        "client_secret_post",
                        "none"), // default is client_secret_basic // TODO make configureble and
                // validate it against client registration
                "token_endpoint_auth_signing_alg_values_supported",
                Set.of(), // if jwt authentication is used, the value is required. // TODO
                 "display_values_supported", config.displayValueSupported,
                // "claim_types_supported",  null,
                // "claims_supported", null,
                // "service_documentation", null, // TODO
                // "claims_locales_supported", null,
                // "ui_locales_supported", null, // TODO
                "claims_parameter_supported",
                false,
                "request_parameter_supported",
                false,
                // "request_uri_parameter_supported", // the parameter is false,
                // oidcc-basic-certification-test-plan	will be failed.
                // false,
                "require_request_uri_registration",
                false,
                // "op_policy_uri", null,　// TODO
                // "op_tos_uri", null // TODO
                "code_challenge_methods_supported",
                Set.of(CodeChallengeMethod.PLAIN.name(), CodeChallengeMethod.S256.name()));
    }
}
