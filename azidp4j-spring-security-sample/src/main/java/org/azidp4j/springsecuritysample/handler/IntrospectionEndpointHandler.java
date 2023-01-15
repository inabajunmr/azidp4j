package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.azidp4j.springsecuritysample.authentication.ClientAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class IntrospectionEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IntrospectionEndpointHandler.class);

    private final AzIdP azIdP;

    private final ClientAuthenticator clientAuthenticator;

    @Autowired
    public IntrospectionEndpointHandler(AzIdP azIdP, ClientStore clientStore) {
        this.azIdP = azIdP;
        this.clientAuthenticator =
                new ClientAuthenticator(clientStore, ClientAuthenticator.Endpoint.introspection);
    }

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc7662">https://datatracker.ietf.org/doc/html/rfc7662</a>
     */
    @PostMapping(value = "introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(
            HttpServletRequest request, @RequestParam MultiValueMap<String, Object> body) {
        LOGGER.info(IntrospectionEndpointHandler.class.getName());

        // just client authentication
        if (clientAuthenticator.authenticateClient(request).isEmpty()) {
            return ResponseEntity.status(401).build();
        }

        // Introspection Request
        var response = azIdP.introspect(new IntrospectionRequest(body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
