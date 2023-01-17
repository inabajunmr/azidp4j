package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.revocation.request.RevocationRequest;
import org.azidp4j.springsecuritysample.authentication.ClientAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class RevocationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationHandler.class);

    private final AzIdP azIdP;

    private final ClientAuthenticator clientAuthenticator;

    @Autowired
    public RevocationHandler(AzIdP azIdP, ClientStore clientStore) {
        this.azIdP = azIdP;
        this.clientAuthenticator =
                new ClientAuthenticator(clientStore, ClientAuthenticator.Endpoint.revocation);
    }

    /**
     * @see <a
     *     href="https://www.rfc-editor.org/rfc/rfc7009">https://www.rfc-editor.org/rfc/rfc7009</a>
     */
    @PostMapping(value = "revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map> revoke(
            HttpServletRequest request, @RequestParam MultiValueMap<String, Object> body) {
        LOGGER.info(RevocationHandler.class.getName());

        // When client is unauthenticated, azidp4j accepts null as authenticatedClientId.
        // If client isn't public client, azidp4j returns error against revocation request without
        // authenticated client.
        var clientOpt = clientAuthenticator.authenticateClient(request);
        String authenticatedClientId = null;
        if (clientOpt.isPresent()) {
            authenticatedClientId = clientOpt.get().clientId;
        }

        // Revocation Request
        var response =
                azIdP.revoke(new RevocationRequest(authenticatedClientId, body.toSingleValueMap()));

        // azidp4j responses status code and response body.
        return ResponseEntity.status(response.status).body(response.body);
    }
}
