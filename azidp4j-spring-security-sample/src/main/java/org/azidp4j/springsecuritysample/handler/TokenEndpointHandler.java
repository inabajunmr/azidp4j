package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.springsecuritysample.authentication.ClientAuthenticator;
import org.azidp4j.token.request.TokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class TokenEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenEndpointHandler.class);

    private final AzIdP azIdP;

    private final ClientAuthenticator clientAuthenticator;

    @Autowired
    public TokenEndpointHandler(AzIdP azIdP, ClientStore clientStore) {
        this.azIdP = azIdP;
        this.clientAuthenticator =
                new ClientAuthenticator(clientStore, ClientAuthenticator.Endpoint.token);
    }

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">https://datatracker.ietf.org/doc/html/rfc6749#section-3.2</a>
     * @see <a
     *     href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint</a>
     */
    @PostMapping(value = "token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> tokenEndpoint(
            HttpServletRequest request, @RequestParam MultiValueMap<String, Object> body) {
        LOGGER.info(TokenEndpointHandler.class.getName());

        // When client is unauthenticated, azidp4j accepts null as authenticatedClientId.
        // If client isn't public client, azidp4j returns error against token request without
        // authenticated client.
        var clientOpt = clientAuthenticator.authenticateClient(request);
        String authenticatedClientId = null;
        if (clientOpt.isPresent()) {
            authenticatedClientId = clientOpt.get().clientId;
        }

        // Token Request
        var response =
                azIdP.issueToken(new TokenRequest(authenticatedClientId, body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
