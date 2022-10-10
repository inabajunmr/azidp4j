package org.azidp4j.springsecuritysample.authentication;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.token.TokenEndpointAuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

@Component
public class ClientAuthenticator {

    @Autowired ClientStore clientStore;

    private final BasicAuthenticationConverter authenticationConverter =
            new BasicAuthenticationConverter();

    public Optional<Client> authenticateClient(
            HttpServletRequest request, MultiValueMap<String, String> body) {
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
                    return client;
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
                    return client;
                }
            }
        }

        return Optional.empty();
    }
}
