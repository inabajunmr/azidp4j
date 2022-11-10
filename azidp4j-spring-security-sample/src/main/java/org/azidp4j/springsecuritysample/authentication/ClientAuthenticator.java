package org.azidp4j.springsecuritysample.authentication;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class ClientAuthenticator {

    @Autowired ClientStore clientStore;

    private final BasicAuthenticationConverter authenticationConverter =
            new BasicAuthenticationConverter();

    /**
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">https://datatracker.ietf.org/doc/html/rfc6749#section-2.3</a>
     */
    public Optional<Client> authenticateClient(HttpServletRequest request) {
        // attempt basic authentication
        {
            var usernamePasswordAuthenticationToken = authenticationConverter.convert(request);
            if (usernamePasswordAuthenticationToken != null) {
                var client = clientStore.find(usernamePasswordAuthenticationToken.getName());
                // if client supports token_endpoint_auth_method=client_secret_basic,
                // verify client secret.
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
        // ref. https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
        // Alternatively, the authorization server MAY support including the client credentials in
        // the request-body using the following parameters:
        if (request.getParameterMap().containsKey("client_id")) {
            var clientId = request.getParameterMap().get("client_id")[0];
            var client = clientStore.find(clientId);

            // if client supports token_endpoint_auth_method=client_secret_post,
            // verify client secret.
            if (client.isPresent()
                    && client.get().tokenEndpointAuthMethod
                            == TokenEndpointAuthMethod.client_secret_post
                    && request.getParameterMap().containsKey("client_secret")) {

                // verify client secret
                if (client.get()
                        .clientSecret
                        .equals(request.getParameterMap().get("client_secret")[0])) {
                    return client;
                }
            }
        }

        return Optional.empty();
    }
}
