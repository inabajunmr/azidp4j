package org.azidp4j.springsecuritysample.handler;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwksEndpointHandler.class);

    @Autowired JWKSet jwkSet;

    /**
     * @see <a
     *     href="https://www.rfc-editor.org/rfc/rfc7517">https://www.rfc-editor.org/rfc/rfc7517</a>
     */
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        LOGGER.info(JwksEndpointHandler.class.getName());
        return jwkSet.toPublicJWKSet().toJSONObject();
    }
}
