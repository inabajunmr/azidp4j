package org.azidp4j.springsecuritysample;

import org.azidp4j.client.Client;
import org.azidp4j.client.ClientValidator;

public class JwtClientAuthNotAllowClientValidator implements ClientValidator {
    @Override
    public void validate(Client client) {
        // The implementation only supports client_secret_basic and client_secret_post.
        if (client.tokenEndpointAuthMethod != null) {
            switch (client.tokenEndpointAuthMethod) {
                case private_key_jwt, client_secret_jwt -> throw new IllegalArgumentException();
            }
        }
    }
}
