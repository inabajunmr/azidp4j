package org.azidp4j;

public class AzIdPConfig {

    public final String issuer;
    public String accessTokenKid;
    public int accessTokenExpirationSec;

    public AzIdPConfig(String issuer, String accessTokenKid, int accessTokenExpirationSec) {
        this.issuer = issuer;
        this.accessTokenKid = accessTokenKid;
        this.accessTokenExpirationSec = accessTokenExpirationSec;
    }
}
