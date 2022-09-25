package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DynamicClientRegistrationEndpointHandler {

    @Autowired AzIdP azIdP;

    @Autowired ClientStore clientStore;

    @PostMapping("/client")
    public ResponseEntity<Map<String, Object>> register(
            @RequestBody Map<String, Object> requestBody) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken) {
            // TODO test
            var req = azIdP.parseClientRegistrationRequest(requestBody);
            var response = azIdP.registerClient(req);
            return ResponseEntity.status(response.status).body(response.body);
        } else {
            return ResponseEntity.status(401).build();
        }
    }
}
