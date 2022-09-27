package org.azidp4j.springsecuritysample.handler;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksEndpointHandler {

    @Autowired JWKSet jwkSet;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return jwkSet.toPublicJWKSet().toJSONObject();
    }
}
