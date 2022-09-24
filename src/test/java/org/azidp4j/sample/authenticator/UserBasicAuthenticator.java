package org.azidp4j.sample.authenticator;

import com.sun.net.httpserver.BasicAuthenticator;

public class UserBasicAuthenticator extends BasicAuthenticator {

    public UserBasicAuthenticator() {
        super("user");
    }

    @Override
    public boolean checkCredentials(String username, String password) {
        return switch (username) {
            case "user1" -> password.equals("password1");
            case "user2" -> password.equals("password2");
            case "user3" -> password.equals("password3");
            default -> false;
        };
    }
}
