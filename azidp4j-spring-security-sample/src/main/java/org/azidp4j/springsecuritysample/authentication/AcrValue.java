package org.azidp4j.springsecuritysample.authentication;

public enum AcrValue {
    self_reported("urn:azidp4j:loa:0fa:self-reported", "/login/self-reported"),
    pwd("urn:azidp4j:loa:1fa:pwd", "/login");

    public final String value;
    public final String path;

    AcrValue(String value, String path) {
        this.value = value;
        this.path = path;
    }
}
