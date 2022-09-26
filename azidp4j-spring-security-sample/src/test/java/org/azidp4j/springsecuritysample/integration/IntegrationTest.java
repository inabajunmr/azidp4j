package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.GrantType;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = "server.port=8080")
public class IntegrationTest {

    private final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void exampleTest() throws IOException {
        TestRestTemplate testRestTemplate =
                new TestRestTemplate(TestRestTemplate.HttpClientOption.ENABLE_COOKIES);
        var defaultClient = testRestTemplate.withBasicAuth("default", "default");

        // token request by default client
        MultiValueMap<String, String> tokenRequest = new LinkedMultiValueMap<>();
        tokenRequest.add("grant_type", "client_credentials");
        tokenRequest.add("scope", "default");
        var tokenRequestEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequest);
        var tokenResponse =
                defaultClient.postForEntity(
                        "http://localhost:8080/token", tokenRequestEntity, Map.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        var at = (String) tokenResponse.getBody().get("access_token");

        // client registration
        var redirectUri = "http://example.com";
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
                        "scope1 scope2 openid");
        var clientRegistrationEntity =
                RequestEntity.post("/client")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + at)
                        .body(clientRegistrationRequest);
        var clientRegistrationResponse =
                testRestTemplate.postForEntity(
                        "http://localhost:8080/client", clientRegistrationEntity, Map.class);
        assertThat(clientRegistrationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        var clientId = (String) clientRegistrationResponse.getBody().get("client_id");

        // authorization request
        var state = UUID.randomUUID().toString();
        var authzReq =
                UriComponentsBuilder.fromPath("/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("scope", "scope1 openid")
                        .queryParam("state", state)
                        .build();

        var authorizationResponse =
                testRestTemplate.getForEntity(
                        "http://localhost:8080" + authzReq.toString(), String.class);
        assertThat(authorizationResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        // redirect to login form
        var login =
                testRestTemplate.getForEntity(
                        authorizationResponse.getHeaders().get("Location").get(0), String.class);
        var loginPage = Jsoup.parse(login.getBody());
        assertThat(loginPage.select("form").attr("action")).isEqualTo("/login");
        var csrf = loginPage.select("input[name='_csrf']").val();

        // post login
        MultiValueMap<String, String> loginBody = new LinkedMultiValueMap<>();
        loginBody.add("username", "user");
        loginBody.add("password", "password");
        loginBody.add("_csrf", csrf);
        var loginRequestEntity =
                RequestEntity.post(authorizationResponse.getHeaders().get("Location").get(0))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(loginBody);
        var loginResponseEntity =
                testRestTemplate.postForEntity(
                        "http://localhost:8080" + "/login", loginRequestEntity, String.class);

        // redirect to authorization request
        ResponseEntity<String> authorizationResponse2 =
                testRestTemplate.exchange(
                        RequestEntity.get(loginResponseEntity.getHeaders().get("Location").get(0))
                                .build(),
                        String.class);

        // redirect to consent page
        var consent =
                testRestTemplate.getForEntity(
                        authorizationResponse2.getHeaders().get("Location").get(0), String.class);
        var consentPage = Jsoup.parse(consent.getBody());
        var csrf2 = consentPage.select("input[name='_csrf']").val();

        // post consent
        MultiValueMap<String, String> consentBody = new LinkedMultiValueMap<>();
        consentBody.add("_csrf", csrf2);
        var consentRequestEntity =
                RequestEntity.post(authorizationResponse2.getHeaders().get("Location").get(0))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(consentBody);
        var consentResponseEntity =
                testRestTemplate.postForEntity(
                        authorizationResponse2.getHeaders().get("Location").get(0),
                        consentRequestEntity,
                        String.class);

        // redirect to authorization request
        ResponseEntity<String> authorizationResponse3 =
                testRestTemplate.exchange(
                        RequestEntity.get(consentResponseEntity.getHeaders().get("Location").get(0))
                                .build(),
                        String.class);
        System.out.println(consentResponseEntity);

        // TODO authorization request
        // TODO login
        // TODO consent
        // TODO token request
        // TODO refresh token

    }
}
