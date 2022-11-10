package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IntrospectionEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IntrospectionEndpointHandler.class);

    @Autowired AzIdP azIdP;

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc7662">https://datatracker.ietf.org/doc/html/rfc7662</a>
     */
    @RequestMapping(
            value = "/introspect",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(
            @RequestParam MultiValueMap<String, Object> body, Authentication authentication) {
        LOGGER.info(IntrospectionEndpointHandler.class.getName());

        // Introspection endpoint requires client authentication.
        // ref. org.azidp4j.springsecuritysample.authentication.ClientAuthenticationFilter
        // ref. org.azidp4j.springsecuritysample.authentication.ClientAuthenticator
        if (!authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_CLIENT"))) {
            return ResponseEntity.status(401).build();
        }

        // Introspection Request
        var response = azIdP.introspect(new IntrospectionRequest(body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
