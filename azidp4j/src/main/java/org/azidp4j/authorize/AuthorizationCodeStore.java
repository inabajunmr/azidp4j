package org.azidp4j.authorize;

import java.util.Optional;

public interface AuthorizationCodeStore {

    void save(AuthorizationCode code);

    Optional<AuthorizationCode> consume(String code);
}
