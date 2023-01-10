package org.azidp4j.client;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.util.HumanReadable;

public class Client {

    public final String clientId;
    public final String clientSecret;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<String> redirectUris;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<Set<ResponseType>> responseTypes;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final ApplicationType applicationType;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<GrantType> grantTypes;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> clientName;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String clientUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String logoUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String scope;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final List<String> contacts;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> tosUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> policyUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String jwksUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final JWKSet jwks;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareId;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareVersion;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final TokenEndpointAuthMethod tokenEndpointAuthMethod;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final SigningAlgorithm tokenEndpointAuthSigningAlg;

    /** No definition at spec but used like tokenEndpointAuthMethod */
    public final TokenEndpointAuthMethod introspectionEndpointAuthMethod;

    /** No definition at spec but used like tokenEndpointAuthSigningAlg */
    public final SigningAlgorithm introspectionEndpointAuthSigningAlg;

    /** No definition at spec but used like tokenEndpointAuthMethod */
    public final TokenEndpointAuthMethod revocationEndpointAuthMethod;

    /** No definition at spec but used like tokenEndpointAuthSigningAlg */
    public final SigningAlgorithm revocationEndpointAuthSigningAlg;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final SigningAlgorithm idTokenSignedResponseAlg;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Long defaultMaxAge;

    /**
     * OpenID Connect Dynamic Client Registration 1.0
     *
     * <p>but AzIdP4J ignores this and always returns auth_time.
     */
    public final Boolean requireAuthTime;

    public List<String> defaultAcrValues;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String initiateLoginUri;

    public boolean isConfidentialClient() {
        return !tokenEndpointAuthMethod.equals(TokenEndpointAuthMethod.none);
    }

    public Client(
            String clientId,
            String clientSecret,
            Set<String> redirectUris,
            Set<Set<ResponseType>> responseTypes,
            ApplicationType applicationType,
            Set<GrantType> grantTypes,
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
            TokenEndpointAuthMethod tokenEndpointAuthMethod,
            SigningAlgorithm tokenEndpointAuthSigningAlg,
            TokenEndpointAuthMethod introspectionEndpointAuthMethod,
            SigningAlgorithm introspectionEndpointAuthSigningAlg,
            TokenEndpointAuthMethod revocationEndpointAuthMethod,
            SigningAlgorithm revocationEndpointAuthSigningAlg,
            SigningAlgorithm idTokenSignedResponseAlg,
            Long defaultMaxAge,
            Boolean requireAuthTime,
            List<String> defaultAcrValues,
            String initiateLoginUri) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = redirectUris;
        this.responseTypes = responseTypes;
        this.applicationType = applicationType;
        this.grantTypes = grantTypes;
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
}
