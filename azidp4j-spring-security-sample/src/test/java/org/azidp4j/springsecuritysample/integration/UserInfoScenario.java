package org.azidp4j.springsecuritysample.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class UserInfoScenario {

    public static void test(
            String endpoint, TestRestTemplate testRestTemplate, String accessToken) {
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
    }
}
