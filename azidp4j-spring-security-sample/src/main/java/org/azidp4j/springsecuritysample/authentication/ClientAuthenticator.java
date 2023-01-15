package org.azidp4j.springsecuritysample.authentication;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import org.azidp4j.client.Client;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.TokenEndpointAuthMethod;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

public class ClientAuthenticator {

    private final ClientStore clientStore;

    private final Endpoint endpoint;

    private final BasicAuthenticationConverter authenticationConverter =
            new BasicAuthenticationConverter();

    public ClientAuthenticator(ClientStore clientStore, Endpoint endpoint) {
        this.clientStore = clientStore;
        this.endpoint = endpoint;
    }

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
                        && authMethod(client.get())
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
                    && authMethod(client.get()) == TokenEndpointAuthMethod.client_secret_post
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

    private TokenEndpointAuthMethod authMethod(Client client) {
        return switch (endpoint) {
            case token -> client.tokenEndpointAuthMethod;
            case introspection -> client.introspectionEndpointAuthMethod;
            case revocation -> client.revocationEndpointAuthMethod;
        };
    }

    public enum Endpoint {
        token,
        introspection,
        revocation;
    }
}
