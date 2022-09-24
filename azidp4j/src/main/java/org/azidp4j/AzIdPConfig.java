package org.azidp4j;

public class AzIdPConfig {

    public final String issuer;
    public final String accessTokenKid;
    public final String idTokenKid;
    public final int accessTokenExpirationSec;
    public final int idTokenExpirationSec;
    public final int refreshTokenExpirationSec;

    public AzIdPConfig(
            String issuer,
            String accessTokenKid,
            String idTokenKid,
            int accessTokenExpirationSec,
            int refreshTokenExpirationSec,
            int idTokenExpirationSec) {
        this.issuer = issuer;
        this.accessTokenKid = accessTokenKid;
        this.idTokenKid = idTokenKid;
        this.accessTokenExpirationSec = accessTokenExpirationSec;
        this.refreshTokenExpirationSec = refreshTokenExpirationSec;
        this.idTokenExpirationSec = idTokenExpirationSec;
    }
}
