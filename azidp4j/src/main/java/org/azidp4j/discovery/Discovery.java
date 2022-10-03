package org.azidp4j.discovery;

import java.util.Map;
import java.util.Set;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.authorize.CodeChallengeMethod;
import org.azidp4j.util.MapUtil;

public class Discovery {

    private final AzIdPConfig config;

    public Discovery(AzIdPConfig config) {
        this.config = config;
    }

    public Map<String, Object> metadata() {
        return MapUtil.nullRemovedMap(
                "issuer",
                config.issuer,
                "authorization_endpoint",
                config.authorizationEndpoint,
                "token_endpoint",
                config.tokenEndpoint,
                "userinfo_endpoint",
                config.userInfoEndpoint,
                "jwks_uri",
                config.jwksEndpoint,
                "registration_endpoint",
                config.clientRegistrationEndpoint,
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
                "response_modes_supported",
                Set.of("query", "fragment"),
                "grant_types_supported",
                Set.of("authorization_code", "implicit"),
                // "acr_values_supported", null,
                "subject_types_supported",
                Set.of("public"),
                "id_token_signing_alg_values_supported",
                Set.of("ES256"),
                // "id_token_encryption_alg_values_supported", null,
                // "id_token_encryption_enc_values_supported", null,
                // "userinfo_signing_alg_values_supported", null,
                // "userinfo_encryption_alg_values_supported",null,
                // "userinfo_encryption_enc_values_supported", null,
                // "request_object_signing_alg_values_supported", null,
                // "request_object_encryption_alg_values_supported", null,
                // "request_object_encryption_enc_values_supported", null,
                "token_endpoint_auth_methods_supported",
                Set.of("client_secret_basic"),
                // "token_endpoint_auth_signing_alg_values_supported",  null,
                // "display_values_supported", null,
                // "claim_types_supported",  null,
                // "claims_supported", null,
                // "service_documentation", null,
                // "claims_locales_supported", null,
                // "ui_locales_supported", null,
                // "claims_parameter_supported", null,
                // "request_parameter_supported", null,
                // "request_uri_parameter_supported", null,
                // "require_request_uri_registration", null,
                // "op_policy_uri", null,
                // "op_tos_uri", null
                "code_challenge_methods_supported",
                Set.of(CodeChallengeMethod.PLAIN.name(), CodeChallengeMethod.S256.name()));
    }
}
