package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.token.request.TokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class TokenEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenEndpointHandler.class);

    @Autowired AzIdP azIdP;

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">https://datatracker.ietf.org/doc/html/rfc6749#section-3.2</a>
     * @see <a
     *     href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint</a>
     */
    @PostMapping(value = "token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> tokenEndpoint(@RequestParam MultiValueMap<String, Object> body) {
        LOGGER.info(TokenEndpointHandler.class.getName());

        // When client is unauthenticated, azidp4j accepts null as authenticatedClientId.
        // If client isn't public client, azidp4j returns error against token request without
        // authenticated cilent.
        String authenticatedClientId = null;
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null
                && auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_CLIENT"))) {
            authenticatedClientId = auth.getName();
        }

        // Token Request
        var response =
                azIdP.issueToken(new TokenRequest(authenticatedClientId, body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
