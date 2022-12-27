package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import org.azidp4j.authorize.authorizationcode.AuthorizationCodeService;
import org.azidp4j.authorize.authorizationcode.jwt.JwtAuthorizationCodeService;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.azidp4j.token.refreshtoken.RefreshTokenService;
import org.azidp4j.token.refreshtoken.jwt.JwtRefreshTokenService;
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

        // client registration ========================
        var redirectUri = "https://example.com";
        var clientRegistrationResponse =
                ClientRegistrationScenario.test(
                        endpoint, testRestTemplate, defaultClientAccessToken, redirectUri);
        var clientId = (String) clientRegistrationResponse.getBody().get("client_id");
        var clientSecret = (String) clientRegistrationResponse.getBody().get("client_secret");
        var configurationToken =
                (String) clientRegistrationResponse.getBody().get("registration_access_token");
        var configurationUri =
                (String) clientRegistrationResponse.getBody().get("registration_client_uri");

        // read client ========================
        {
            var clientReadEntity =
                    RequestEntity.get(configurationUri)
                            .accept(MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + configurationToken)
                            .build();
            var clientReadResponse = testRestTemplate.exchange(clientReadEntity, Map.class);
            assertThat(clientReadResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        // authorization request with login and consent ========================
        String authorizationCode =
                AuthorizationRequestScenario.test(
                        endpoint, testRestTemplate, redirectUri, clientId);

        // token request by authorization code ========================
        ResponseEntity<Map> tokenResponseForAuthorizationCodeGrant =
                TokenRequestByAuthorizationCode.test(
                        endpoint,
                        testRestTemplate,
                        redirectUri,
                        clientId,
                        clientSecret,
                        authorizationCode);
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
        IntrospectionScenario.test(
                accessToken, testRestTemplate, clientId, clientSecret, endpoint, true);

        // userinfo ========================
        UserInfoScenario.test(endpoint, testRestTemplate, accessToken);

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
