package org.azidp4j.authorize;

public interface AuthorizationCodeStore {

    void save(AuthorizationCode code);

    AuthorizationCode consume(String code);
}
