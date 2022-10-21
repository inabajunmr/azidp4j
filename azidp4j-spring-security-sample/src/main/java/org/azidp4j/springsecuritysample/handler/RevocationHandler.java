package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.springsecuritysample.authentication.ClientAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RevocationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationHandler.class);

    @Autowired ClientAuthenticator clientAuthenticator;

    @Autowired AzIdP azIdP;

    @RequestMapping(
            value = "/revoke",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> revoke(
            HttpServletRequest request, @RequestParam MultiValueMap<String, String> body) {
        LOGGER.info(RevocationHandler.class.getName());

        String authenticatedClientId = null;
        var client =
                clientAuthenticator.authenticateClient(
                        request,
                        body); // TODO should be filter like BearerTokenBodyAuthenticationFilter?
        if (client.isPresent()) {
            authenticatedClientId = client.get().clientId;
        }

        var response =
                azIdP.revoke(new RevocationRequest(authenticatedClientId, body.toSingleValueMap()));
        return ResponseEntity.status(response.status).body(response.body);
    }
}
