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
        return MapUtil.nullRemovedMap(
                "issuer",
                config.issuer, // TODO validate (no fragment and query)
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
                Set.of(
                        "code",
                        "token",
                        "id_token",
                        "code token",
                        "code id_token",
                        "id_token token",
                        "code id_token token"),
                "response_modes_supported", // default is query and fragment
                Set.of("query", "fragment"),
                "grant_types_supported",
                config.grantTypesSupported,
                // "acr_values_supported", null,
                "subject_types_supported",
                Set.of("public"),
                "id_token_signing_alg_values_supported",
                Set.of("ES256", "RS256", "none"),
                "id_token_encryption_alg_values_supported",
                Set.of(),
                "id_token_encryption_enc_values_supported",
                Set.of(),
                "userinfo_signing_alg_values_supported",
                Set.of(),
                "userinfo_encryption_alg_values_supported",
                Set.of(),
                "userinfo_encryption_enc_values_supported",
                Set.of(),
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
                        "none"), // default is client_secret_basic
                "token_endpoint_auth_signing_alg_values_supported",
                Set.of(), // if jwt authentication is used, the value is required.
                // "display_values_supported", null,
                // "claim_types_supported",  null,
                // "claims_supported", null,
                // "service_documentation", null,
                // "claims_locales_supported", null,
                // "ui_locales_supported", null,
                "claims_parameter_supported",
                false,
                "request_parameter_supported",
                false,
                //                "request_uri_parameter_supported", // the parameter is false,
                // oidcc-basic-certification-test-plan	will be failed.
                //                false,
                "require_request_uri_registration",
                false,
                // "op_policy_uri", null,
                // "op_tos_uri", null
                "code_challenge_methods_supported",
                Set.of(CodeChallengeMethod.PLAIN.name(), CodeChallengeMethod.S256.name()));
    }
}
