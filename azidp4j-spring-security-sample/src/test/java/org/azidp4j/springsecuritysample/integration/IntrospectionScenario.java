package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class IntrospectionScenario {

    public static void test(
            String accessToken,
            TestRestTemplate testRestTemplate,
            String clientId,
            String clientSecret,
            String endpoint,
            boolean expected) {
        MultiValueMap<String, String> introspectionRequest = new LinkedMultiValueMap<>();
        introspectionRequest.add("token", accessToken);
        var introspectionRequestEntity =
                RequestEntity.post("/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .body(introspectionRequest);
        var introspectionResponse =
                testRestTemplate
                        .withBasicAuth(clientId, clientSecret)
                        .postForEntity(
                                endpoint + "/introspect", introspectionRequestEntity, Map.class);
        assertThat(introspectionResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertEquals(expected, introspectionResponse.getBody().get("active"));
    }
}
