package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.web.util.UriComponentsBuilder;

public class AuthorizationRequestWithAcrClaimsParameterScenario {
    public static String test(
            String endpoint,
            TestRestTemplate testRestTemplate,
            String redirectUri,
            String clientId) {
        // authorization request ========================
        // id_token contains gender via claims parameter. userinfo returns email, email_verified via
        // scope and phone_number via claims parameter.
        var claims =
                "{\"id_token\":{\"gender\":null, \"acr\":{\"essential\":true,"
                    + "\"values\":[\"urn:azidp4j:loa:0fa:self-reported\"]}},\"userinfo\":{\"phone_number\":{\"essential\":true}}}";
        var state = UUID.randomUUID().toString();
        var authorizationRequest =
                UriComponentsBuilder.fromUriString(endpoint + "/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("scope", "scope1 openid email")
                        .queryParam("claims", "{claims}")
                        .queryParam("state", state)
                        .build(claims);
        var authorizationResponseRedirectToLoginPage =
                testRestTemplate.getForEntity(authorizationRequest, String.class);
        assertThat(authorizationResponseRedirectToLoginPage.getStatusCode())
                .isEqualTo(HttpStatus.FOUND);

        // redirect to authorization request ========================
        var authorizationResponseWithAuthorizationCode =
                authorizationResponseRedirectToLoginPage.getHeaders().get("Location").get(0);
        var authorizationCode =
                UriComponentsBuilder.fromUriString(authorizationResponseWithAuthorizationCode)
                        .build()
                        .getQueryParams()
                        .get("code")
                        .get(0);
        return authorizationCode;
    }
}
