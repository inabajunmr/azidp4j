package org.azidp4j.springsecuritysample.handler;

import java.time.Instant;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.azidp4j.token.TokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class TokenEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenEndpointHandler.class);

    private final BasicAuthenticationConverter authenticationConverter =
            new BasicAuthenticationConverter();

    @Autowired ClientStore clientStore;

    @Autowired AzIdP azIdP;

    @RequestMapping(
            value = "/token",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> tokenEndpoint(
            HttpServletRequest request, @RequestParam MultiValueMap<String, String> body) {
        LOGGER.info(TokenEndpointHandler.class.getName());

        // attempt basic authentication
        String authenticatedClientId = null;
        {
            var usernamePasswordAuthenticationToken = authenticationConverter.convert(request);
            if (usernamePasswordAuthenticationToken != null) {
                var client = clientStore.find(usernamePasswordAuthenticationToken.getName());
                if (client.isPresent()
                        && client.get()
                                .clientSecret
                                .equals(usernamePasswordAuthenticationToken.getCredentials())
                        && client.get().tokenEndpointAuthMethod
                                == TokenEndpointAuthMethod.client_secret_basic) {
                    authenticatedClientId = client.get().clientId;
                }
            }
        }

        // attempt body authentication
        if (authenticatedClientId == null && body.containsKey("client_id")) {
            var clientId = body.get("client_id").get(0);
            var client = clientStore.find(clientId);
            if (client.isPresent()
                    && client.get().tokenEndpointAuthMethod
                            == TokenEndpointAuthMethod.client_secret_post
                    && body.containsKey("client_secret")) {
                if (client.get().clientSecret.equals(body.get("client_secret").get(0))) {
                    authenticatedClientId = client.get().clientId;
                }
            }
        }

        var response =
                azIdP.issueToken(
                        new TokenRequest(
                                authenticatedClientId,
                                Instant.now().getEpochSecond(),
                                body.toSingleValueMap()));
        return ResponseEntity.status(response.status).body(response.body);
    }
}
