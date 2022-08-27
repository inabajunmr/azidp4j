package org.azidp4j.sample;

import com.sun.net.httpserver.HttpServer;
import org.azidp4j.AzIdP;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class SampleTest {
    @Test
    void test() throws IOException, InterruptedException {
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

        // token request
        var tokenRequest = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/token"))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=code&code=xxx&redirect_uri=http://example.com&client_id=sample"))
                .setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8").build();
        var tokenResponse = client.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(tokenResponse.body());

        // shutdown authorization server
        az.stop();
    }
}
