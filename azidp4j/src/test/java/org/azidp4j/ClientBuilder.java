package org.azidp4j;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.*;
import org.azidp4j.util.HumanReadable;

/** For testing */
public class ClientBuilder {

    private String clientId;

    private String clientSecret;

    private Set<String> redirectUris;

    private Set<Set<ResponseType>> responseTypes;

    private ApplicationType applicationType;

    private Set<GrantType> grantTypes;

    private HumanReadable<String> clientName;

    private String clientUri;

    private String logoUri;

    private String scope;

    private List<String> contacts;

    private HumanReadable<String> tosUri;

    private HumanReadable<String> policyUri;

    private String jwksUri;

    private JWKSet jwks;

    private String softwareId;

    private String softwareVersion;

    private TokenEndpointAuthMethod tokenEndpointAuthMethod;

    private String tokenEndpointAuthSigningAlg;

    private SigningAlgorithm idTokenSignedResponseAlg;

    private Long defaultMaxAge;

    private Boolean requireAuthTime;

    private List<String> defaultAcrValues;

    private String initiateLoginUri;

    public Client build() {
        if (ClientBuilder.class.getDeclaredFields().length
                != Client.class.getDeclaredFields().length) {
            throw new AssertionError("ClientBuilder should supports unknown field");
        }
        return new Client(
                clientId,
                clientSecret,
                redirectUris,
                responseTypes,
                applicationType,
                grantTypes,
                clientName,
                clientUri,
                logoUri,
                scope,
                contacts,
                tosUri,
                policyUri,
                jwksUri,
                jwks,
                softwareId,
                softwareVersion,
                tokenEndpointAuthMethod,
                tokenEndpointAuthSigningAlg,
                idTokenSignedResponseAlg,
                defaultMaxAge,
                requireAuthTime,
                defaultAcrValues,
                initiateLoginUri);
    }

    public static ClientBuilder builder() {
        return new ClientBuilder();
    }

    public ClientBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ClientBuilder clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public ClientBuilder redirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
        return this;
    }

    public ClientBuilder responseTypes(Set<Set<ResponseType>> responseTypes) {
        this.responseTypes = responseTypes;
        return this;
    }

    public ClientBuilder applicationType(ApplicationType applicationType) {
        this.applicationType = applicationType;
        return this;
    }

    public ClientBuilder grantTypes(Set<GrantType> grantTypes) {
        this.grantTypes = grantTypes;
        return this;
    }

    public ClientBuilder clientName(HumanReadable<String> clientName) {
        this.clientName = clientName;
        return this;
    }

    public ClientBuilder clientUri(String clientUri) {
        this.clientUri = clientUri;
        return this;
    }

    public ClientBuilder logoUri(String logoUri) {
        this.logoUri = logoUri;
        return this;
    }

    public ClientBuilder scope(String scope) {
        this.scope = scope;
        return this;
    }

    public ClientBuilder contacts(List<String> contacts) {
        this.contacts = contacts;
        return this;
    }

    public ClientBuilder tosUri(HumanReadable<String> tosUri) {
        this.tosUri = tosUri;
        return this;
    }

    public ClientBuilder policyUri(HumanReadable<String> policyUri) {
        this.policyUri = policyUri;
        return this;
    }

    public ClientBuilder jwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
        return this;
    }

    public ClientBuilder jwks(JWKSet jwks) {
        this.jwks = jwks;
        return this;
    }

    public ClientBuilder softwareId(String softwareId) {
        this.softwareId = softwareId;
        return this;
    }

    public ClientBuilder softwareVersion(String softwareVersion) {
        this.softwareVersion = softwareVersion;
        return this;
    }

    public ClientBuilder tokenEndpointAuthMethod(TokenEndpointAuthMethod tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public ClientBuilder tokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
        return this;
    }

    public ClientBuilder idTokenSignedResponseAlg(SigningAlgorithm idTokenSignedResponseAlg) {
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
        return this;
    }

    public ClientBuilder defaultMaxAge(Long defaultMaxAge) {
        this.defaultMaxAge = defaultMaxAge;
        return this;
    }

    public ClientBuilder requireAuthTime(Boolean requireAuthTime) {
        this.requireAuthTime = requireAuthTime;
        return this;
    }

    public ClientBuilder defaultAcrValues(List<String> defaultAcrValues) {
        this.defaultAcrValues = defaultAcrValues;
        return this;
    }

    public ClientBuilder initiateLoginUri(String initiateLoginUri) {
        this.initiateLoginUri = initiateLoginUri;
        return this;
    }
}
