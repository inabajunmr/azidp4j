package org.azidp4j.token;

public interface UserPasswordVerifier {

    /**
     * when username and password is correct, return true.
     *
     * @param username
     * @param password
     * @return
     */
    boolean verify(String username, String password);
}
