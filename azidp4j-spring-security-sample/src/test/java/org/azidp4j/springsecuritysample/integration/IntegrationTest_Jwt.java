package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.jwt.JwtAuthorizationCodeService;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.jwt.JwtRefreshTokenService;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
            "server.port=8081",
            "endpoint=http://localhost:8081",
            "spring.main.allow-bean-definition-overriding=true"
        })
public class IntegrationTest_Jwt {

    @TestConfiguration
    static class TokenServiceConfiguration {
        @Autowired JWKSet jwkSet;

        @Value("${endpoint}")
        private String endpoint;

        @Bean
        @Primary
        public AccessTokenService accessTokenService() {
            return new JwtAccessTokenService(jwkSet, endpoint, () -> "123");
        }

        @Bean
        @Primary
        public RefreshTokenService refreshTokenService() {
            return new JwtRefreshTokenService(jwkSet, endpoint, () -> "123");
        }

        @Bean
        @Primary
        public AuthorizationCodeService authorizationCodeService() {
            return new JwtAuthorizationCodeService(jwkSet, endpoint, () -> "123");
        }
    }

    @Test
    void exampleTest() throws IOException, ParseException, JOSEException {
        String endpoint = "http://localhost:8081";
        TestRestTemplate testRestTemplate =
                new TestRestTemplate(TestRestTemplate.HttpClientOption.ENABLE_COOKIES);

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
                testRestTemplate
                        .withBasicAuth("default", "default")
                        .postForEntity(endpoint + "/token", tokenRequestEntity, Map.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        var defaultClientAccessToken = (String) tokenResponse.getBody().get("access_token");

        // client registration
        var redirectUri = "https://example.com";
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
                        "client_secret_basic");
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
        var clientId = (String) clientRegistrationResponse.getBody().get("client_id");
        var clientSecret = (String) clientRegistrationResponse.getBody().get("client_secret");
        var configurationToken =
                (String) clientRegistrationResponse.getBody().get("registration_access_token");
        var configurationUri =
                (String) clientRegistrationResponse.getBody().get("registration_client_uri");

        // read client
        {
            var clientReadEntity =
                    RequestEntity.get(configurationUri)
                            .accept(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + configurationToken)
                            .build();
            var clientReadResponse = testRestTemplate.exchange(clientReadEntity, Map.class);
            assertThat(clientReadResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

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

        // token request by authorization code ========================
        MultiValueMap<String, String> tokenRequestForAuthorizationCodeGrant =
                new LinkedMultiValueMap<>();
        tokenRequestForAuthorizationCodeGrant.add("grant_type", "authorization_code");
        tokenRequestForAuthorizationCodeGrant.add("code", authorizationCode);
        tokenRequestForAuthorizationCodeGrant.add("redirect_uri", redirectUri);
        tokenRequestForAuthorizationCodeGrant.add("client_id", clientId);
        var tokenRequestForAuthorizationCodeGrantEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequestForAuthorizationCodeGrant);
        var tokenResponseForAuthorizationCodeGrant =
                testRestTemplate
                        .withBasicAuth(clientId, clientSecret)
                        .postForEntity(
                                endpoint + "/token",
                                tokenRequestForAuthorizationCodeGrantEntity,
                                Map.class);
        assertThat(tokenResponseForAuthorizationCodeGrant.getStatusCode()).isEqualTo(HttpStatus.OK);
        var accessToken =
                (String) tokenResponseForAuthorizationCodeGrant.getBody().get("access_token");
        var idToken = (String) tokenResponseForAuthorizationCodeGrant.getBody().get("id_token");
        var refreshToken =
                (String) tokenResponseForAuthorizationCodeGrant.getBody().get("refresh_token");
        var jwks = JWKSet.load(new URL(endpoint + "/.well-known/jwks.json"));
        var parsedIdToken = JWSObject.parse(idToken);
        var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
        var verifier = new RSASSAVerifier((RSAKey) jwk);
        assertTrue(parsedIdToken.verify(verifier));
        // gender claims is from claims parameter
        assertEquals(parsedIdToken.getPayload().toJSONObject().get("gender"), "user1gender");

        // introspection ========================
        {
            IntegrationTestUtil.introspectionTest(
                    accessToken, testRestTemplate, clientId, clientSecret, endpoint, true);
        }

        // userinfo endpoint(get) ========================
        {
            var userInfoRequest =
                    RequestEntity.get(endpoint + "/userinfo")
                            .accept(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + accessToken)
                            .build();
            var userinfo = testRestTemplate.exchange(userInfoRequest, Map.class);
            assertThat(userinfo.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(userinfo.getBody().get("sub")).isEqualTo("user1");
            // email claim from scope
            assertThat(userinfo.getBody().get("email")).isEqualTo("user1@example.com");
            // phone_number claim from claims parameter
            assertThat(userinfo.getBody().get("phone_number")).isEqualTo("+1 (425) 555-1212");
        }

        // userinfo endpoint(post with header bearer token) ========================
        {
            var userInfoRequest =
                    RequestEntity.post(endpoint + "/userinfo")
                            .accept(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + accessToken)
                            .build();
            var userinfo = testRestTemplate.exchange(userInfoRequest, Map.class);
            assertThat(userinfo.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(userinfo.getBody().get("sub")).isEqualTo("user1");
            // email claim from scope
            assertThat(userinfo.getBody().get("email")).isEqualTo("user1@example.com");
            // phone_number claim from claims parameter
            assertThat(userinfo.getBody().get("phone_number")).isEqualTo("+1 (425) 555-1212");
        }

        // userinfo endpoint(post with body bearer token) ========================
        {
            MultiValueMap<String, String> userinfoRequest = new LinkedMultiValueMap<>();
            userinfoRequest.add("access_token", accessToken);
            var userinfoRequestEntity =
                    RequestEntity.post("/userinfo")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .accept(MediaType.APPLICATION_JSON)
                            .body(userinfoRequest);
            var userinfo =
                    testRestTemplate.postForEntity(
                            endpoint + "/userinfo", userinfoRequestEntity, Map.class);
            assertThat(userinfo.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(userinfo.getBody().get("sub")).isEqualTo("user1");
            // email claim from scope
            assertThat(userinfo.getBody().get("email")).isEqualTo("user1@example.com");
            // phone_number claim from claims parameter
            assertThat(userinfo.getBody().get("phone_number")).isEqualTo("+1 (425) 555-1212");
        }

        // token refresh ========================
        MultiValueMap<String, String> tokenRequestForRefresh = new LinkedMultiValueMap<>();
        tokenRequestForRefresh.add("grant_type", "refresh_token");
        tokenRequestForRefresh.add("refresh_token", refreshToken);
        tokenRequestForRefresh.add("scope", "scope1");
        var tokenRequestForRefreshEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequestForRefresh);
        var tokenResponseForRefreshGrant =
                testRestTemplate
                        .withBasicAuth(clientId, clientSecret)
                        .postForEntity(
                                endpoint + "/token", tokenRequestForRefreshEntity, Map.class);
        assertThat(tokenResponseForRefreshGrant.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertNotNull(tokenResponseForRefreshGrant.getBody().get("access_token"));
        assertNotNull(tokenResponseForRefreshGrant.getBody().get("refresh_token"));

        // delete client ========================
        var clientDeleteEntity =
                RequestEntity.delete(configurationUri)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + configurationToken)
                        .build();
        var clientDeleteResponse = testRestTemplate.exchange(clientDeleteEntity, Map.class);
        assertThat(clientDeleteResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }
}
