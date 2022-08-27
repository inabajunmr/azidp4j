package org.azidp4j.sample;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpServer;
import org.azidp4j.AzIdP;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SampleTest {
    @Test
    void test() throws IOException, InterruptedException, ParseException, JOSEException {
        // setup authorization server
        var az = new SampleAz();
        az.start(8080);

        // authorization request
        var client = HttpClient.newHttpClient();
        var authorizationRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/authorize?response_type=code&client_id=sample&redirect_uri=http://example.com&scope=test&state=xyz"))
                .GET().build();
        var authorizationResponse = client.send(authorizationRequest, HttpResponse.BodyHandlers.ofString());
        var location = authorizationResponse.headers().firstValue("Location").get();
        System.out.println(location);
        var redirectQuery = URI.create(location).getQuery();
        var queryMap = Arrays.stream(redirectQuery.split("&"))
                .map(kv -> kv.split("="))
                .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));

        // token request
        var tokenRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/token"))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=code&code=" + queryMap.get("code") + "&redirect_uri=http://example.com&client_id=sample"))
                .setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8").build();
        var tokenResponse = client.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
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
