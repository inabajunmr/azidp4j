package org.azidp4j;

public class AzIdPConfig {

    public final String issuer;
    public final String accessTokenKid;
    public final int accessTokenExpirationSec;
    public final int refreshTokenExpirationSec;

    public AzIdPConfig(
            String issuer,
            String accessTokenKid,
            int accessTokenExpirationSec,
            int refreshTokenExpirationSec) {
        this.issuer = issuer;
        this.accessTokenKid = accessTokenKid;
        this.accessTokenExpirationSec = accessTokenExpirationSec;
        this.refreshTokenExpirationSec = refreshTokenExpirationSec;
    }
}
