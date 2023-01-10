package org.azidp4j.client.request;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.Set;
import org.azidp4j.util.HumanReadable;

public class InternalClientRequest {

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final Set<String> redirectUris;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final Set<String> grantTypes;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final Set<String> responseTypes;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String applicationType;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final HumanReadable<String> clientName;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final String clientUri;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final String logoUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String scope;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final List<String> contacts;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final HumanReadable<String> tosUri;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final HumanReadable<String> policyUri;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final String jwksUri;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final JWKSet jwks;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with PPID
    // public final String sectorIdentifierUri;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with PPID
    // public final String subjectType;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareId;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareVersion;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String tokenEndpointAuthMethod;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol / OpenID Connect Dynamic Client Registration
     * 1.0
     */
    public final String tokenEndpointAuthSigningAlg;

    public final String introspectionEndpointAuthMethod;

    public final String introspectionEndpointAuthSigningAlg;

    public final String revocationEndpointAuthMethod;

    public final String revocationEndpointAuthSigningAlg;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String idTokenSignedResponseAlg;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with encrypted id token
    // public final String idTokenEncryptedResponseAlg;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with signed userinfo
    // public final String userinfoSignedResponseAlg;
    // userinfo_encrypted_response_alg
    // userinfo_encrypted_response_enc

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with signed request object
    // request_object_signing_alg

    // TODO supports with encrypted request object
    // request_object_encryption_alg
    // request_object_encryption_enc

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO support maxAge override
    public final Long defaultMaxAge;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Boolean requireAuthTime;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final List<String> defaultAcrValues;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String initiateLoginUri;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    // TODO supports with request object
    // public final String request_uris;

    public static Builder builder() {
        return new Builder();
    }

    private InternalClientRequest(
            Set<String> redirectUris,
            Set<String> grantTypes,
            Set<String> responseTypes,
            String applicationType,
            HumanReadable<String> clientName,
            String clientUri,
            String logoUri,
            String scope,
            List<String> contacts,
            HumanReadable<String> tosUri,
            HumanReadable<String> policyUri,
            String jwksUri,
            JWKSet jwks,
            String softwareId,
            String softwareVersion,
            String tokenEndpointAuthMethod,
            String tokenEndpointAuthSigningAlg,
            String introspectionEndpointAuthMethod,
            String introspectionEndpointAuthSigningAlg,
            String revocationEndpointAuthMethod,
            String revocationEndpointAuthSigningAlg,
            String idTokenSignedResponseAlg,
            Long defaultMaxAge,
            Boolean requireAuthTime,
            List<String> defaultAcrValues,
            String initiateLoginUri) {
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.applicationType = applicationType;
        this.clientName = clientName;
        this.clientUri = clientUri;
        this.logoUri = logoUri;
        this.scope = scope;
        this.contacts = contacts;
        this.tosUri = tosUri;
        this.policyUri = policyUri;
        this.jwksUri = jwksUri;
        this.jwks = jwks;
        this.softwareId = softwareId;
        this.softwareVersion = softwareVersion;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
        this.introspectionEndpointAuthMethod = introspectionEndpointAuthMethod;
        this.introspectionEndpointAuthSigningAlg = introspectionEndpointAuthSigningAlg;
        this.revocationEndpointAuthMethod = revocationEndpointAuthMethod;
        this.revocationEndpointAuthSigningAlg = revocationEndpointAuthSigningAlg;
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
        this.defaultMaxAge = defaultMaxAge;
        this.requireAuthTime = requireAuthTime;
        this.defaultAcrValues = defaultAcrValues;
        this.initiateLoginUri = initiateLoginUri;
    }

    public static class Builder {
        private Set<String> redirectUris;
        private Set<String> grantTypes;
        private Set<String> responseTypes;
        private String applicationType;
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
        private String tokenEndpointAuthMethod;
        private String tokenEndpointAuthSigningAlg;
        private String introspectionEndpointAuthMethod;
        private String introspectionEndpointAuthSigningAlg;
        private String revocationEndpointAuthMethod;
        private String revocationEndpointAuthSigningAlg;
        private String idTokenSignedResponseAlg;
        private Long defaultMaxAge;
        private Boolean requireAuthTime;
        public List<String> defaultAcrValues;
        private String initiateLoginUri;

        public Builder redirectUris(Set<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public Builder grantTypes(Set<String> grantTypes) {
            this.grantTypes = grantTypes;
            return this;
        }

        public Builder responseTypes(Set<String> responseTypes) {
            this.responseTypes = responseTypes;
            return this;
        }

        public Builder applicationType(String applicationType) {
            this.applicationType = applicationType;
            return this;
        }

        public Builder clientName(HumanReadable<String> clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder clientUri(String clientUri) {
            this.clientUri = clientUri;
            return this;
        }

        public Builder logoUri(String logoUri) {
            this.logoUri = logoUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder contacts(List<String> contacts) {
            this.contacts = contacts;
            return this;
        }

        public Builder tosUri(HumanReadable<String> tosUri) {
            this.tosUri = tosUri;
            return this;
        }

        public Builder policyUri(HumanReadable<String> policyUri) {
            this.policyUri = policyUri;
            return this;
        }

        public Builder jwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public Builder jwks(JWKSet jwks) {
            this.jwks = jwks;
            return this;
        }

        public Builder softwareId(String softwareId) {
            this.softwareId = softwareId;
            return this;
        }

        public Builder softwareVersion(String softwareVersion) {
            this.softwareVersion = softwareVersion;
            return this;
        }

        public Builder tokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
            return this;
        }

        public Builder tokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
            this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
            return this;
        }

        public Builder idTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
            this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
            return this;
        }

        public Builder defaultMaxAge(Long defaultMaxAge) {
            this.defaultMaxAge = defaultMaxAge;
            return this;
        }

        public Builder requireAuthTime(Boolean requireAuthTime) {
            this.requireAuthTime = requireAuthTime;
            return this;
        }

        public Builder initiateLoginUri(String initiateLoginUri) {
            this.initiateLoginUri = initiateLoginUri;
            return this;
        }

        public Builder defaultAcrValues(List<String> defaultAcrValues) {
            this.defaultAcrValues = defaultAcrValues;
            return this;
        }

        public InternalClientRequest build() {
            return new InternalClientRequest(
                    redirectUris,
                    grantTypes,
                    responseTypes,
                    applicationType,
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
                    introspectionEndpointAuthMethod,
                    introspectionEndpointAuthSigningAlg,
                    revocationEndpointAuthMethod,
                    revocationEndpointAuthSigningAlg,
                    idTokenSignedResponseAlg,
                    defaultMaxAge,
                    requireAuthTime,
                    defaultAcrValues,
                    initiateLoginUri);
        }
    }
}
