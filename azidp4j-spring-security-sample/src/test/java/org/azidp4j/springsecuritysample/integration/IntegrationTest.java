package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class IntegrationTest {

    @Test
    void exampleTest(@Autowired TestRestTemplate restTemplate) {
        var defaultClient = restTemplate.withBasicAuth("default", "default");
        MultiValueMap<String, String> tokenRequest = new LinkedMultiValueMap<>();
        tokenRequest.add("grant_type", "client_credentials");
        tokenRequest.add("scope", "default");
        var requestEntity =
                RequestEntity.post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(tokenRequest);
        var tokenResponse = defaultClient.postForEntity("/token", requestEntity, Map.class);
        System.out.println(tokenResponse.getBody());
        // TODO verify
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        // TODO token request by default client
        // TODO create client
        // TODO authorization request
        // TODO login
        // TODO consent
        // TODO token request
        // TODO refresh token
        String body = restTemplate.getForObject("/", String.class);

        assertThat(body).isEqualTo("Hello World");
    }
}
