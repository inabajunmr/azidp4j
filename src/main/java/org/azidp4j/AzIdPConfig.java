package org.azidp4j;

public class AzIdPConfig {

    public final String issuer;
    public String accessTokenKid;


    public AzIdPConfig(String issuer, String accessTokenKid) {
        this.issuer = issuer;
        this.accessTokenKid = accessTokenKid;
    }
}
