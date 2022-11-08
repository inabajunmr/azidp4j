package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.token.request.TokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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
            HttpServletRequest request, @RequestParam MultiValueMap<String, Object> body) {
        LOGGER.info(TokenEndpointHandler.class.getName());

        // attempt basic authentication
        String authenticatedClientId = null;
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null
                && auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_CLIENT"))) {
            authenticatedClientId = auth.getName();
        }
        var response =
                azIdP.issueToken(new TokenRequest(authenticatedClientId, body.toSingleValueMap()));
        return ResponseEntity.status(response.status).body(response.body);
    }
}
