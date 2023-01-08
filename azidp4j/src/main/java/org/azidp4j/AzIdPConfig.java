package org.azidp4j;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.ResponseMode;
import org.azidp4j.authorize.request.ResponseType;
import org.azidp4j.client.GrantType;
import org.azidp4j.client.SigningAlgorithm;
import org.azidp4j.client.TokenEndpointAuthMethod;

public class AzIdPConfig {

    public final String issuer;
    public final Set<String> scopesSupported;
    public final Set<String> defaultScope;
    public final Set<TokenEndpointAuthMethod> tokenEndpointAuthMethodsSupported;
    public final Set<SigningAlgorithm> tokenEndpointAuthSigningAlgValuesSupported;
    public final Set<TokenEndpointAuthMethod> introspectionEndpointAuthMethodsSupported;
    public final Set<SigningAlgorithm> introspectionEndpointAuthSigningAlgValuesSupported;
    public final Set<TokenEndpointAuthMethod> revocationEndpointAuthMethodsSupported;
    public final Set<SigningAlgorithm> revocationEndpointAuthSigningAlgValuesSupported;
    public final Set<GrantType> grantTypesSupported;
    public final Set<Set<ResponseType>> responseTypeSupported;
    public final Set<ResponseMode> responseModesSupported;
    public final Set<SigningAlgorithm> idTokenSigningAlgValuesSupported;
    public final List<String> acrValuesSupported;
    public final Duration authorizationCodeExpiration;
    public final Duration accessTokenExpiration;
    public final Duration idTokenExpiration;
    public final Duration refreshTokenExpiration;

    public AzIdPConfig(
            String issuer,
            Set<String> scopesSupported,
            Set<String> defaultScope,
            Set<TokenEndpointAuthMethod> tokenEndpointAuthMethodsSupported,
            Set<SigningAlgorithm> tokenEndpointAuthSigningAlgValuesSupported,
            Set<TokenEndpointAuthMethod> introspectionEndpointAuthMethodsSupported,
            Set<SigningAlgorithm> introspectionEndpointAuthSigningAlgValuesSupported,
            Set<TokenEndpointAuthMethod> revocationEndpointAuthMethodsSupported,
            Set<SigningAlgorithm> revocationEndpointAuthSigningAlgValuesSupported,
            Set<GrantType> grantTypesSupported,
            Set<Set<ResponseType>> responseTypeSupported,
            Set<ResponseMode> responseModesSupported,
            Set<SigningAlgorithm> idTokenSigningAlgValuesSupported,
            List<String> acrValuesSupported,
            Duration accessTokenExpiration,
            Duration authorizationCodeExpiration,
            Duration refreshTokenExpiration,
            Duration idTokenExpiration) {
        this.issuer = issuer;
        this.scopesSupported = scopesSupported;
        this.defaultScope = defaultScope;
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        this.tokenEndpointAuthSigningAlgValuesSupported =
                tokenEndpointAuthSigningAlgValuesSupported;
        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
        this.introspectionEndpointAuthSigningAlgValuesSupported =
                introspectionEndpointAuthSigningAlgValuesSupported;
        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
        this.revocationEndpointAuthSigningAlgValuesSupported =
                revocationEndpointAuthSigningAlgValuesSupported;
        this.grantTypesSupported = grantTypesSupported;
        this.responseTypeSupported = responseTypeSupported;
        this.responseModesSupported = responseModesSupported;
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        this.acrValuesSupported = acrValuesSupported;
        this.accessTokenExpiration = accessTokenExpiration;
        this.authorizationCodeExpiration = authorizationCodeExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.idTokenExpiration = idTokenExpiration;
    }
}
