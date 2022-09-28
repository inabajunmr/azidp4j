package org.azidp4j.springsecuritysample.handler;

import java.time.Instant;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.token.TokenRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class TokenEndpointHandler {

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

        var usernamePasswordAuthenticationToken = authenticationConverter.convert(request);
        var client = clientStore.find(usernamePasswordAuthenticationToken.getName());
        String authenticatedClientId = null;
        if (client != null
                && client.clientSecret.equals(
                        usernamePasswordAuthenticationToken.getCredentials())) {
            authenticatedClientId = client.clientId;
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
