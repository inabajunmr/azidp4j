package org.azidp4j.sample.authenticator;

import com.sun.net.httpserver.BasicAuthenticator;

public class UserBasicAuthenticator extends BasicAuthenticator {

    public UserBasicAuthenticator() {
        super("user");
    }

    @Override
    public boolean checkCredentials(String username, String password) {
        switch (username) {
            case "user1":
                return password.equals("password1");
            case "user2":
                return password.equals("password2");
            case "user3":
                return password.equals("password3");
        }
        return false;
    }
}
