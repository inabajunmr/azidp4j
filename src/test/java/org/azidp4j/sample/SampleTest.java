package org.azidp4j.sample;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.BasicAuthenticator;
import com.sun.net.httpserver.HttpServer;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.GrantType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SampleTest {
    @Test
    void test() throws IOException, InterruptedException, ParseException, JOSEException {
        // setup authorization server
        var az = new SampleAz();
        az.start(8080);
        var defaultClient = HttpClient.newBuilder().authenticator(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("default", "default".toCharArray());
            }
        }).build();

        // client credentials
        var clientCredentialsTokenRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/token"))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope=default"))
                .setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8").build();
        var clientCredentialsTokenResponse = defaultClient.send(clientCredentialsTokenRequest, HttpResponse.BodyHandlers.ofString());
        var clientAccessToken = new ObjectMapper().readTree(clientCredentialsTokenResponse.body()).get("access_token").textValue();

        // client registration
        var clientRegistrationClient= HttpClient.newHttpClient();
        var clientBody = Map.of("redirect_uris", Set.of("http://example.com"),
                "grant_types", Set.of(GrantType.authorization_code.name()),
                "response_types", Set.of(ResponseType.code.name()),
                "scope", "scope1 scope2");
        var clientRegistrationRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/client"))
                .header("Authorization", "Bearer " + clientAccessToken)
                .POST(HttpRequest.BodyPublishers.ofString(new ObjectMapper().writeValueAsString(clientBody))).build();
        var clientRegistrationResponse = clientRegistrationClient.send(clientRegistrationRequest, HttpResponse.BodyHandlers.ofString());
        var registeredClient = new ObjectMapper().readTree(clientRegistrationResponse.body());
        var clientId = registeredClient.get("client_id").asText();
        var clientSecret = registeredClient.get("client_secret").asText();

        // authorization request
        var authorizationRequestClient = HttpClient.newHttpClient();
        var authorizationRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/authorize?response_type=code&client_id=sample&redirect_uri=http://example.com&scope=test&state=xyz"))
                .GET().build();
        var authorizationResponse = authorizationRequestClient.send(authorizationRequest, HttpResponse.BodyHandlers.ofString());
        var location = authorizationResponse.headers().firstValue("Location").get();
        System.out.println(location);
        var redirectQuery = URI.create(location).getQuery();
        var queryMap = Arrays.stream(redirectQuery.split("&"))
                .map(kv -> kv.split("="))
                .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));

        // token request
        var tokenRequestClient = HttpClient.newBuilder().authenticator(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(clientId, clientSecret.toCharArray());
            }
        }).build();
        var tokenRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/token"))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=" + queryMap.get("code") + "&redirect_uri=http://example.com&client_id=sample"))
                .setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8").build();
        var tokenResponse = tokenRequestClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(tokenResponse.body());

        // verify token
        var jwks = JWKSet.load(new URL("http://localhost:8080/jwks"));
        var tokenResponseJSON = new ObjectMapper().readTree(tokenResponse.body());
        var accessToken = tokenResponseJSON.get("access_token");
        var parsedAccessToken = JWSObject.parse(accessToken.asText());
        var jwk = jwks.getKeyByKeyId(parsedAccessToken.getHeader().getKeyID());
        var verifier = new ECDSAVerifier((ECKey)jwk);
        assertTrue(parsedAccessToken.verify(verifier));

        // shutdown authorization server
        az.stop();
    }
}
