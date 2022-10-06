package org.azidp4j.springsecuritysample.handler;

import java.util.HashMap;
import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class DynamicClientRegistrationEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DynamicClientRegistrationEndpointHandler.class);

    @Autowired AzIdP azIdP;

    @Autowired ClientStore clientStore;

    @PostMapping("/client")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody Map<String, Object> requestBody) {
        LOGGER.info(DynamicClientRegistrationEndpointHandler.class.getName() + " register");
        var requestWithScope = requestBody;
        if (!requestBody.containsKey("scope")) {
            requestWithScope = new HashMap<>(requestBody);
            requestWithScope.put("scope", "openid");
        }
        var req = azIdP.parseClientRegistrationRequest(requestWithScope);
        var response = azIdP.registerClient(req);
        return ResponseEntity.status(response.status).body(response.body);
    }

    @PostMapping("/client/{client_id}")
    public ResponseEntity<Map<String, Object>> configure(
            @PathVariable("client_id") String clientId,
            @RequestBody Map<String, Object> requestBody) {
        LOGGER.info(DynamicClientRegistrationEndpointHandler.class.getName() + " configure");
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof BearerTokenAuthentication && auth.getName().equals(clientId)) {
            var req = azIdP.parseClientConfigurationRequest(auth.getName(), requestBody);
            var response = azIdP.configureRequest(req);
            return ResponseEntity.status(response.status).body(response.body);
        } else {
            return ResponseEntity.status(401).build();
        }
    }

    @DeleteMapping("/client/{client_id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable("client_id") String clientId) {
        LOGGER.info(DynamicClientRegistrationEndpointHandler.class.getName() + " delete");
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof BearerTokenAuthentication && auth.getName().equals(clientId)) {
            var response = azIdP.delete(auth.getName());
            return ResponseEntity.status(response.status).body(response.body);
        } else {
            return ResponseEntity.status(401).build();
        }
    }
}
