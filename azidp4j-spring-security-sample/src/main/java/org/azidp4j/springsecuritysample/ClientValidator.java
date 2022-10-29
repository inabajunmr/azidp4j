package org.azidp4j.springsecuritysample;

import org.azidp4j.client.Client;

public class ClientValidator implements org.azidp4j.client.ClientValidator {
    @Override
    public void validate(Client client) {
        if (client.tokenEndpointAuthMethod != null) {
            switch (client.tokenEndpointAuthMethod) {
                case private_key_jwt -> throw new IllegalArgumentException();
                case client_secret_jwt -> throw new IllegalArgumentException();
            }
        }
    }
}
