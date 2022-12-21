package org.azidp4j.token.idtoken;

/** ID Token is invalid. */
public class InvalidIDTokenException extends RuntimeException {

    public InvalidIDTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidIDTokenException(String message) {
        super(message);
    }
}
