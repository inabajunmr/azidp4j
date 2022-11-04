package org.azidp4j;

import java.time.Duration;
import java.util.Set;

public class AzIdPConfig {

    public final String issuer;
    public final Set<String> scopesSupported;
    public final Set<String> defaultScope;
    public final Duration authorizationCodeExpiration;
    public final Duration accessTokenExpiration;
    public final Duration idTokenExpiration;
    public final Duration refreshTokenExpiration;

    public AzIdPConfig(
            String issuer,
            Set<String> scopesSupported,
            Set<String> defaultScope,
            Duration accessTokenExpiration,
            Duration authorizationCodeExpiration,
            Duration refreshTokenExpiration,
            Duration idTokenExpiration) {
        this.issuer = issuer;
        this.scopesSupported = scopesSupported;
        this.defaultScope = defaultScope;
        this.accessTokenExpiration = accessTokenExpiration;
        this.authorizationCodeExpiration = authorizationCodeExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.idTokenExpiration = idTokenExpiration;
    }
}
