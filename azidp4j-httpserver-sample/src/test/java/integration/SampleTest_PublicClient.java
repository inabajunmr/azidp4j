package integration;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.RSAKey;
import httpserversample.SampleAz;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SampleTest_PublicClient {
    @Test
    void test() throws IOException, InterruptedException, ParseException, JOSEException {
        // setup authorization server
        var az = new SampleAz();
        az.start(8080);
        var httpClient = HttpClient.newBuilder().build();

        // client credentials
        var clientCredentialsTokenRequest =
                HttpRequest.newBuilder(URI.create("http://localhost:8080/token"))
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        "grant_type=client_credentials&scope=default"))
                        .setHeader(
                                "Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                        .setHeader(
                                "Authorization",
                                "Basic "
                                        + Base64.getEncoder()
                                                .encodeToString(
                                                        "default:default"
                                                                .getBytes(StandardCharsets.UTF_8)))
                        .build();
        var clientCredentialsTokenResponse =
                httpClient.send(
                        clientCredentialsTokenRequest, HttpResponse.BodyHandlers.ofString());
        var clientAccessToken =
                new ObjectMapper()
                        .readTree(clientCredentialsTokenResponse.body())
                        .get("access_token")
                        .textValue();

        // client registration
        var clientRegistrationClient = HttpClient.newHttpClient();
        var clientBody =
                Map.of(
                        "redirect_uris",
                        Set.of("http://localhost:8080"),
                        "grant_types",
                        Set.of(
                                GrantType.authorization_code.name(),
                                GrantType.implicit.name(),
                                GrantType.password.name(),
                                GrantType.refresh_token.name()),
                        "application_type",
                        "native",
                        "response_types",
                        Set.of(ResponseType.code.name(), ResponseType.token.name()),
                        "scope",
                        "scope1 scope2 openid",
                        "token_endpoint_auth_method",
                        // public client
                        "none");
        var clientRegistrationRequest =
                HttpRequest.newBuilder(URI.create("http://localhost:8080/client"))
                        .header("Authorization", "Bearer " + clientAccessToken)
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        new ObjectMapper().writeValueAsString(clientBody)))
                        .build();
        var clientRegistrationResponse =
                clientRegistrationClient.send(
                        clientRegistrationRequest, HttpResponse.BodyHandlers.ofString());
        var registeredClient = new ObjectMapper().readTree(clientRegistrationResponse.body());
        var clientId = registeredClient.get("client_id").asText();
        Assertions.assertFalse(registeredClient.has("client_secret"));

        var authorizationRequestClient = HttpClient.newBuilder().build();

        // authorization code grant
        {
            var consent = new ObjectMapper().writeValueAsString(Map.of(clientId, "scope1 openid"));
            var authorizationRequest =
                    HttpRequest.newBuilder(
                                    URI.create(
                                            "http://localhost:8080/authorize?response_type=code&client_id="
                                                    + clientId
                                                    + "&redirect_uri=http://localhost:8080&scope=scope1%20openid&state=xyz&nonce=abc"
                                                    + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                            .GET()
                            .header(
                                    "Cookie",
                                    "Login=user1; AuthTime="
                                            + Instant.now().getEpochSecond()
                                            + "; Consent="
                                            + consent)
                            .build();
            var authorizationResponse =
                    authorizationRequestClient.send(
                            authorizationRequest, HttpResponse.BodyHandlers.ofString());
            var location = authorizationResponse.headers().firstValue("Location").get();
            System.out.println(location);
            var redirectQuery = URI.create(location).getQuery();
            var queryMap =
                    Arrays.stream(redirectQuery.split("&"))
                            .map(kv -> kv.split("="))
                            .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));

            // token request
            var tokenRequest =
                    HttpRequest.newBuilder(URI.create("http://localhost:8080/token"))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            "grant_type=authorization_code&code="
                                                    + queryMap.get("code")
                                                    + "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&redirect_uri=http://localhost:8080&client_id="
                                                    + clientId))
                            .setHeader(
                                    "Content-Type",
                                    "application/x-www-form-urlencoded; charset=utf-8")
                            .build();
            var tokenResponse = httpClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());

            // verify access token
            // signature
            var jwks = JWKSet.load(new URL("http://localhost:8080/jwks"));
            System.out.println(tokenResponse.body());
            var tokenResponseJSON = new ObjectMapper().readTree(tokenResponse.body());
            var accessToken = tokenResponseJSON.get("access_token");
            assertNotNull(accessToken.asText());

            // verify id token
            var idToken = tokenResponseJSON.get("id_token");
            var parsedIdToken = JWSObject.parse(idToken.asText());
            var jwk = jwks.getKeyByKeyId(parsedIdToken.getHeader().getKeyID());
            var verifier = new RSASSAVerifier((RSAKey) jwk);
            Assertions.assertTrue(parsedIdToken.verify(verifier));
            var itPayload = parsedIdToken.getPayload().toJSONObject();
            Assertions.assertEquals("user1", itPayload.get("sub"));

            // token refresh
            var refreshToken = tokenResponseJSON.get("refresh_token");

            var refreshTokenRequest =
                    HttpRequest.newBuilder(URI.create("http://localhost:8080/token"))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            "grant_type=refresh_token&refresh_token="
                                                    + refreshToken.textValue()
                                                    + "&client_id="
                                                    + clientId))
                            .setHeader(
                                    "Content-Type",
                                    "application/x-www-form-urlencoded; charset=utf-8")
                            .build();
            var refreshTokenResponse =
                    httpClient.send(refreshTokenRequest, HttpResponse.BodyHandlers.ofString());
            var parsedRefreshTokenResponse =
                    new ObjectMapper().readTree(refreshTokenResponse.body());
            assertNotNull(parsedRefreshTokenResponse.get("access_token").asText());
        }

        // implicit grant
        {
            var consent = new ObjectMapper().writeValueAsString(Map.of(clientId, "scope1"));
            var authorizationRequest =
                    HttpRequest.newBuilder(
                                    URI.create(
                                            "http://localhost:8080/authorize?response_type=token&client_id="
                                                    + clientId
                                                    + "&redirect_uri=http://localhost:8080&scope=scope1&state=xyz"))
                            .GET()
                            .header(
                                    "Cookie",
                                    "Login=user1; AuthTime="
                                            + Instant.now().getEpochSecond()
                                            + "; Consent="
                                            + consent)
                            .build();
            var authorizationResponse =
                    authorizationRequestClient.send(
                            authorizationRequest, HttpResponse.BodyHandlers.ofString());
            var location = authorizationResponse.headers().firstValue("Location").get();
            var fragment = URI.create(location).getFragment();
            var fragmentMap =
                    Arrays.stream(fragment.split("&"))
                            .map(kv -> kv.split("="))
                            .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
            // verify token
            assertNotNull(fragmentMap.get("access_token"));
        }

        // resource owner password credentials grant
        {
            var resourceOwnerPasswordCredentialsTokenRequest =
                    HttpRequest.newBuilder(URI.create("http://localhost:8080/token"))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            "grant_type=password&scope=scope1&username=user1&password=password1&client_id="
                                                    + clientId))
                            .setHeader(
                                    "Content-Type",
                                    "application/x-www-form-urlencoded; charset=utf-8")
                            .build();
            var resourceOwnerPasswordCredentialResponse =
                    httpClient.send(
                            resourceOwnerPasswordCredentialsTokenRequest,
                            HttpResponse.BodyHandlers.ofString());
            var userAccessToken =
                    new ObjectMapper()
                            .readTree(resourceOwnerPasswordCredentialResponse.body())
                            .get("access_token")
                            .textValue();
            // verify token
            assertNotNull(userAccessToken);
        }

        // shutdown authorization server
        az.stop();
    }
}
