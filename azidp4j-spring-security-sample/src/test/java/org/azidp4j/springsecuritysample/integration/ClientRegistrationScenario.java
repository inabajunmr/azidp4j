package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;

public class ClientRegistrationScenario {

    public static ResponseEntity<Map> test(
            String endpoint,
            TestRestTemplate testRestTemplate,
            String defaultClientAccessToken,
            String redirectUri) {
        var clientRegistrationRequest =
                Map.of(
                        "redirect_uris",
                        Set.of(redirectUri),
                        "grant_types",
                        Set.of(
                                GrantType.authorization_code.name(),
                                GrantType.implicit.name(),
                                GrantType.password.name(),
                                GrantType.refresh_token.name()),
                        "response_types",
                        Set.of(ResponseType.code.name(), ResponseType.token.name()),
                        "scope",
                        "scope1 scope2 openid profile email address phone",
                        "id_token_signed_response_alg",
                        "RS256",
                        "token_endpoint_auth_method",
                        "client_secret_basic",
                        "jwks",
                        ClientJWKs.JWKS.toPublicJWKSet().toJSONObject());
        var clientRegistrationEntity =
                RequestEntity.post("/client")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + defaultClientAccessToken)
                        .body(clientRegistrationRequest);
        var clientRegistrationResponse =
                testRestTemplate.postForEntity(
                        endpoint + "/client", clientRegistrationEntity, Map.class);
        assertThat(clientRegistrationResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return clientRegistrationResponse;
    }
}
