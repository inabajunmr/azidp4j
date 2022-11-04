package org.azidp4j;

import java.time.Duration;
import java.util.Set;
import org.azidp4j.client.GrantType;

public class AzIdPConfig {

    public final String issuer;
    public final Set<String> scopesSupported;
    public final Set<String> defaultScope;
    // TODO client registration validate
    public final Set<GrantType> grantTypesSupported;
    public final Duration authorizationCodeExpiration;
    public final Duration accessTokenExpiration;
    public final Duration idTokenExpiration;
    public final Duration refreshTokenExpiration;

    public AzIdPConfig(
            String issuer,
            Set<String> scopesSupported,
            Set<String> defaultScope,
            Set<GrantType> grantTypesSupported,
            Duration accessTokenExpiration,
            Duration authorizationCodeExpiration,
            Duration refreshTokenExpiration,
            Duration idTokenExpiration) {
        this.issuer = issuer;
        this.scopesSupported = scopesSupported;
        this.defaultScope = defaultScope;
        this.grantTypesSupported = grantTypesSupported;
        this.accessTokenExpiration = accessTokenExpiration;
        this.authorizationCodeExpiration = authorizationCodeExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.idTokenExpiration = idTokenExpiration;
    }
}
