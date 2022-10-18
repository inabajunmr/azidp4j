package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.introspection.IntrospectionRequest;
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
public class IntrospectionEndpointHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(IntrospectionEndpointHandler.class);

    @Autowired ClientAuthenticator clientAuthenticator;

    @Autowired AzIdP azIdP;

    @RequestMapping(
            value = "/introspect",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> introspect(
            HttpServletRequest request, @RequestParam MultiValueMap<String, String> body) {
        LOGGER.info(IntrospectionEndpointHandler.class.getName());

        if (!clientAuthenticator.authenticateClient(request, body).isPresent()) {
            return ResponseEntity.status(401).build();
        }

        var response = azIdP.introspect(new IntrospectionRequest(body.toSingleValueMap()));
        return ResponseEntity.status(response.status).body(response.body);
    }
}
