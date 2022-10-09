package org.azidp4j.token.accesstoken;

import java.util.Set;

public interface AccessToken {
    String getToken();

    String getSub();

    String getScope();

    String getClientId();

    Set<String> getAudience();

    long getExpiresAtEpochSec();

    long getIssuedAtEpochSec();

    String getAuthorizationCode();

    boolean expired();
}
