package org.azidp4j.springsecuritysample.handler;

import java.util.HashMap;
import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.client.request.ClientRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.*;

/**
 * https://www.rfc-editor.org/rfc/rfc7591
 * https://openid.net/specs/openid-connect-registration-1_0.html
 */
@RestController
public class DynamicClientRegistrationEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DynamicClientRegistrationEndpointHandler.class);

    @Autowired AzIdP azIdP;

    /**
     * @see <a
     *     href="https://openid.net/specs/openid-connect-registration-1_0.html">https://openid.net/specs/openid-connect-registration-1_0.html</a>
     * @see <a
     *     href="https://www.rfc-editor.org/rfc/rfc7591">https://www.rfc-editor.org/rfc/rfc7591</a>
     */
    @PostMapping("/client")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody Map<String, Object> requestBody) {
        LOGGER.info(DynamicClientRegistrationEndpointHandler.class.getName() + " register");
        var requestWithScope = requestBody;
        if (!requestBody.containsKey("scope")) {
            // OIDC Conformance test only supports OIDC registration so insert openid scope
            requestWithScope = new HashMap<>(requestBody);
            requestWithScope.put("scope", "openid");
        }

        // Client Registration Request
        var response = azIdP.registerClient(new ClientRequest(requestWithScope));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }

    /** Dynamic Client Registration doesn't define delete but conformance test request like this. */
    @DeleteMapping("/client/{client_id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable("client_id") String clientId) {
        LOGGER.info(DynamicClientRegistrationEndpointHandler.class.getName() + " delete");

        // The endpoint requires authorization by bearer token.
        // Authorization is supported by Spring Security.
        // ref. org.azidp4j.springsecuritysample.SecurityConfiguration
        // ref. org.azidp4j.springsecuritysample.authentication.InternalOpaqueTokenIntrospector
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof BearerTokenAuthentication && auth.getName().equals(clientId)) {
            var response = azIdP.delete(auth.getName());
            return ResponseEntity.status(response.status).body(response.body);
        } else {
            return ResponseEntity.status(401).build();
        }
    }
}
