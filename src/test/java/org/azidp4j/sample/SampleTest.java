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
        var az = new SampleAz();
        az.start(8080);
        var client = HttpClient.newHttpClient();
        var request = HttpRequest.newBuilder(URI
                        .create("http://localhost:8080/authorize?response_type=code&client_id=sample&redirect_uri=http://example.com&scope=test&state=xyz"))
                .GET().build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        var location = response.headers().firstValue("Location").get();
        System.out.println(location);
        az.stop();
    }
}
