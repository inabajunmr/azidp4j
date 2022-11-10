package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.revocation.request.RevocationRequest;
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
public class RevocationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationHandler.class);

    @Autowired AzIdP azIdP;

    @RequestMapping(
            value = "/revoke",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> revoke(
            HttpServletRequest request,
            @RequestParam MultiValueMap<String, Object> body,
            Authentication authentication) {
        LOGGER.info(RevocationHandler.class.getName());

        // When client is unauthenticated, azidp4j accepts null as authenticatedClientId.
        // If client isn't public client, azidp4j returns error.
        String clientId = null;
        if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_CLIENT"))) {
            clientId = authentication.getName();
        }

        // Revocation Request
        var response = azIdP.revoke(new RevocationRequest(clientId, body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
