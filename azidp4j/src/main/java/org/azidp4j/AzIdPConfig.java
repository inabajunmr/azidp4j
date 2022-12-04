package org.azidp4j;

import java.time.Duration;
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
    public final Set<String>
            tokenEndpointAuthSigningAlgValuesSupported; // TODO client registration validate
    public final Set<GrantType> grantTypesSupported;
    public final Set<Set<ResponseType>> responseTypeSupported;
    public final Set<ResponseMode> responseModesSupported;
    public final Set<SigningAlgorithm> idTokenSigningAlgValuesSupported;
    public final Duration authorizationCodeExpiration;
    public final Duration accessTokenExpiration;
    public final Duration idTokenExpiration;
    public final Duration refreshTokenExpiration;

    public AzIdPConfig(
            String issuer,
            Set<String> scopesSupported,
            Set<String> defaultScope,
            Set<TokenEndpointAuthMethod> tokenEndpointAuthMethodsSupported,
            Set<String> tokenEndpointAuthSigningAlgValuesSupported,
            Set<GrantType> grantTypesSupported,
            Set<Set<ResponseType>> responseTypeSupported,
            Set<ResponseMode> responseModesSupported,
            Set<SigningAlgorithm> idTokenSigningAlgValuesSupported,
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
        this.grantTypesSupported = grantTypesSupported;
        this.responseTypeSupported = responseTypeSupported;
        this.responseModesSupported = responseModesSupported;
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        this.accessTokenExpiration = accessTokenExpiration;
        this.authorizationCodeExpiration = authorizationCodeExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.idTokenExpiration = idTokenExpiration;
    }
}
