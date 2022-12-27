package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.UUID;
import org.jsoup.Jsoup;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

public class AuthorizationRequestScenario {
    public static String test(
            String endpoint,
            TestRestTemplate testRestTemplate,
            String redirectUri,
            String clientId) {
        // authorization request ========================
        // id_token contains gender via claims parameter. userinfo returns email, email_verified via
        // scope and phone_number via claims parameter.
        var claims =
                "{\"id_token\":{\"gender\":null},\"userinfo\":{\"phone_number\":{\"essential\":true}}}";
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
        var redirectToLoginPageUri =
                authorizationResponseRedirectToLoginPage.getHeaders().get("Location").get(0);

        // redirect to login form ========================
        var login = testRestTemplate.getForEntity(endpoint + redirectToLoginPageUri, String.class);
        var loginPage = Jsoup.parse(login.getBody());
        assertThat(loginPage.select("form").attr("action")).isEqualTo("/login");
        var csrf = loginPage.select("input[name='_csrf']").val();

        // post login
        MultiValueMap<String, String> loginBody = new LinkedMultiValueMap<>();
        loginBody.add("username", "user1");
        loginBody.add("password", "password1");
        loginBody.add("_csrf", csrf);
        var loginRequestEntity =
                RequestEntity.post(
                                endpoint
                                        + authorizationResponseRedirectToLoginPage
                                                .getHeaders()
                                                .get("Location")
                                                .get(0))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(loginBody);
        var loginResponseEntity =
                testRestTemplate.postForEntity(
                        endpoint + redirectToLoginPageUri, loginRequestEntity, String.class);

        // redirect to authorization request ========================
        ResponseEntity<String> authorizationResponseRedirectToConsentPage =
                testRestTemplate.exchange(
                        RequestEntity.get(
                                        URI.create(
                                                endpoint
                                                        + loginResponseEntity
                                                                .getHeaders()
                                                                .get("Location")
                                                                .get(0)))
                                .build(),
                        String.class);

        // redirect to consent page ========================
        var redirectToConsentPageUri =
                authorizationResponseRedirectToConsentPage.getHeaders().get("Location").get(0);

        var consent =
                testRestTemplate.getForEntity(
                        URI.create(endpoint + redirectToConsentPageUri), String.class);
        var consentPage = Jsoup.parse(consent.getBody());
        var csrf2 = consentPage.select("input[name='_csrf']").val();

        // post consent ========================
        MultiValueMap<String, String> consentBody = new LinkedMultiValueMap<>();
        consentBody.add("_csrf", csrf2);
        var consentRequestEntity =
                RequestEntity.post(redirectToConsentPageUri)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(consentBody);
        var consentResponseEntity =
                testRestTemplate.postForEntity(
                        URI.create(
                                endpoint
                                        + authorizationResponseRedirectToConsentPage
                                                .getHeaders()
                                                .get("Location")
                                                .get(0)),
                        consentRequestEntity,
                        String.class);

        // redirect to authorization request ========================
        ResponseEntity<String> authorizationResponse =
                testRestTemplate.exchange(
                        RequestEntity.get(
                                        URI.create(
                                                endpoint
                                                        + consentResponseEntity
                                                                .getHeaders()
                                                                .get("Location")
                                                                .get(0)))
                                .build(),
                        String.class);
        var authorizationResponseWithAuthorizationCode =
                authorizationResponse.getHeaders().get("Location").get(0);
        var authorizationCode =
                UriComponentsBuilder.fromUriString(authorizationResponseWithAuthorizationCode)
                        .build()
                        .getQueryParams()
                        .get("code")
                        .get(0);
        return authorizationCode;
    }
}
