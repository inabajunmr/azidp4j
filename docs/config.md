# Configuration

All of AzIdP4J functions are defined at [AzIdP](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/AzIdP.java).
To initialize AzIdP instance, use AzIdP#init or AzIdp#initInMemory(for using in-memory stores), AzIdp#initJwt(for using jwt tokens).

These methods return builder so application can configure authorization server or identity provider like this.

```java
var azIdp =
        AzIdP.initInMemory()
                .issuer(endpoint)
                .jwkSet(jwkSet)
                .idTokenKidSupplier(new IdTokenKidSupplier(jwkSet))
                .scopesSupported(Set.of("openid", "user:read"))
                .defaultScopes(Set.of("openid", "scope1"))
                .grantTypesSupported(
                        Set.of(
                                GrantType.authorization_code,
                                GrantType.client_credentials,
                                GrantType.refresh_token))
                .discovery(discoveryConfig)
                .build();
```

## Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L27-L41)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L33-L56)

## Fields

<!-- https://docs.google.com/spreadsheets/d/1MulCF7UbLvtroGYlv-U1cIPEJrRmWptGpmpfrC9gSFM/edit#gid=0 -->

| name | optional | description | value | example |
| --- | --- | --- | --- | --- |
| issuer | required | Identifier of identity provider. The value is used for like JWT iss claim, introspection result. | See OpenID Provider Metadata | https://idp.example.com |
| jwkSet | openid required | JwkSet is keys for signing token like ID Token. The parameter is required when using openid scope. | See [Nimbus JOSE documentation](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/2.13.1/com/nimbusds/jose/jwk/JWKSet.html). | see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/AzIdPConfiguration.java#L142) |
| idTokenKidSupplier | openid required | For choosing which JWK using. The parameter is required when using openid scope. |  | see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/IdTokenKidSupplier.java#L8) |
| scopesSupported | required | Supported scopes for the service. When supporting OpenID Connect, requires `openid` scope. |  | Set.of("openid", "user:read") |
| defaultScopes | optional | Scopes for no scope authorization request. |  | Set.of("openid", "user:read") |
| tokenEndpointAuthMethodsSupported | optional | Suppoted client authentication method for token request. | `client_secret_post` / `client_secret_basic` / `client_secret_jwt` / `private_key_jwt` / `none` | Set.of(TokenEndpointAuthMethod.client_secret_basic) |
| tokenEndpointAuthSigningAlgValuesSupported | optional | Suppoted client authentication signing alg for token request. The value is required when tokenEndpointAuthMethodsSupported is `client_secret_jwt` or `private_key_jwt` |  | Set.of("RS256") |
| introspectionEndpointAuthMethodsSupported | optional | Suppoted client authentication method for introspection request. | `client_secret_post` / `client_secret_basic` / `client_secret_jwt` / `private_key_jwt` / `none` | Set.of(TokenEndpointAuthMethod.client_secret_basic) |
| introspectionEndpointAuthSigningAlgValuesSupported | optional | Suppoted client authentication signing alg for introspection request. The value is required when introspectionEndpointAuthMethodsSupported is `client_secret_jwt` or `private_key_jwt` |  | Set.of("RS256") |
| revocationEndpointAuthMethodsSupported | optional | Suppoted client authentication method for introspection request. | `client_secret_post` / `client_secret_basic` / `client_secret_jwt` / `private_key_jwt` / `none` | Set.of(TokenEndpointAuthMethod.client_secret_basic) |
| revocationEndpointAuthSigningAlgValuesSupported | optional | Suppoted client authentication signing alg for revocation request. The value is required when revocationEndpointAuthMethodsSupported is `client_secret_jwt` or `private_key_jwt` |  | Set.of("RS256") |
| authorizationCodeExpiration | optional | Expiration time for authorization code. Default is 1min. |  | Duration.ofDays(1) |
| accessTokenExpiration | optional | Expiration time for access token. Default is 10min. |  | Duration.ofDays(1) |
| idTokenExpiration | optional | Expiration time for id token. Default is 10min. |  | Duration.ofDays(1) |
| refreshTokenExpiration | optional | Expiration time for refresh token Default is 1day. |  | Duration.ofDays(1) |
| grantTypesSupported | optional | Supported grant types by Authorization Server. Default variables are `authorization_code` and `implicit`. | `authorization_code` / `implicit` / `password` / `client_credential` / `refresh_token` | Set.of(GrantType.authorization_code) |
| responseTypesSupported | optional | Supported response types by Authorization Server. | `code` / `token` / `id_token` / `none` | Set.of(Set.of(ResponseType.code), Set.of(ResponseType.token) |
| responseModesSupported | optional | Supported response modes by Authorization Server. | `query` / `fragment` | Set.of(ResponseMode.query) |
| clientStore | required | See [ClientStore](#clientstore). |  |  |
| clientValidator | optional | See [ClientValidator](#clientvalidator). |  |  |
| clientConfigurationEndpointIssuer | optioanl | Issuing client configuration endpoint. When the value is configured, client registration response has registration_access_token and registration_client_uri. |  |  |
| authorizationCodeService | optional | See [Token Stores Configuration](token-stores-configuration). When supporting `authorization_code grant type, the value is required. |  |  |
| scopeAudienceMapper | required | Mapping scopes to audience. Using for introspection result and JWT aud claim except for ID Token. |  | scope -> Set.of("rs.example.com") |
| accessTokenService | required | See [Token Stores Configuration](token-stores-configuration). |  |  |
| refreshTokenService | optional | See [Token Stores Configuration](token-stores-configuration). When supporting `refresh_token` grant type, the value is required. |  |  |
| discoveryConfig | optional | See [Discovery Configuration](#discovery-configuration). |  |  |
| userPasswordVerifier | optional | See [Password Grant](#password-grant).  When supporting `password` grant type, the value is required. |  |  |

## [ClientStore](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/client/ClientStore.java)

AzIdP4J doesn't provide client persistence except for in-memory implementation.
When application wants to persist client information on another datastore, application needs to implement specific ClientStore interface and configure it like the following example.

```java
var clientStore = new YourClientStore();
AzIdP.init()
    .customClientStore(clientStore)
    ...
    .build();
```

If you want to use in-memory implementation for like testing, you can configure it like this.

```java
var clientStore = new YourClientStore();
AzIdP.init()
    .inMemoryClientStore()
    ...
    .build();
```

## [ClientValidator](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/client/ClientValidator.java)

AzIdP4J validates client while client registration but service-specific restriction can be injected by ClientValidator.
If your service wants to accept only token_endpoint_auth_method=client_secret_basic, define it like the following example.

```java
public class YourClientValidator implements ClientValidator {
    @Override
    public void validate(Client client) {
        // The implementation only supports client_secret_basic and client_secret_post.
        if (client.tokenEndpointAuthMethod != client_secret_basic) {
            throw new IllegalArgumentException();
        }
    }
}
```

Defined class can be configured like this.

```java
var clientValidator = new YourClientValidator();
AzIdP.init()
    .customClientValidator(clientValidator)
    ...
    .build();
```

## Token Stores Configuration

AzIdP4J provides in-memory or JWT token services.
But former isn't practical and later has the restriction that can't support such as token revocation.
If the service wants to store tokens on service specific data store, you can use your service specific implementation.

AzIdP4J has the following services.
See these class's javadoc for implementation requirements.

* [AuthorizationCodeService](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/authorize/authorizationcode/AuthorizationCodeService.java)
* [AccessTokenService](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/token/accesstoken/AccessTokenService.java)
* [RefreshTokenService](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/token/refreshtoken/RefreshTokenService.java)

These implementations can configure like this.

```java
var authorizationCodeService = new YourAuthorizationCodeService();
var accessTokenService = new YourAccessTokenService();
var refreshTokenService = new YourRefreshTokenService();

AzIdP.init()
    .customAuthorizationCodeService(authorizationCodeService)
    .customAccessTokenService(accessTokenService)
    .customRefreshTokenService(refreshTokenService)
    ...
    .build();
```

If you want to use JWT implementations, configure like this.

```java
AzIdP.initJwt()
    .customAuthorizationCodeService(authorizationCodeService)
    ...
    .build();

// If you want to specify only custom authorizationCodeService.
AzIdP.initJwt()
    .customAuthorizationCodeService(authorizationCodeService)
    ...
    .build();
```

## Discovery Configuration

If the service wants to use AzIdp#discovery for Discovery Endpoint, needs to configure discoveryConfig.
[DiscoveryConfigBuilder](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/discovery/DiscoveryConfigBuilder.java) the class for DiscoveryConfig initiation.

```java
var discoveryConfig =
        DiscoveryConfig.builder()
                .authorizationEndpoint("https://idp.example.com/authorize")
                .tokenEndpoint("https://idp.example.com/token")
                .jwksEndpoint("https://idp.example.com/.well-known/jwks.json")
                .clientRegistrationEndpoint("https://idp.example.com/client")
                .userInfoEndpoint("https://idp.example.com/userinfo")
                .displayValueSupported(Set.of(Display.page, Display.popup))
                .build();
AzIdP.init()
    .discoveryConfig(discoveryConfig)
    ...
    .build();
```

Service can only specify supported endpoint.
If the service only supports authorization endpoint and token endpoint, configuration will be like the following example.

```java
var discoveryConfig =
        DiscoveryConfig.builder()
                .authorizationEndpoint("https://idp.example.com/authorize")
                .tokenEndpoint("https://idp.example.com/token")
                .build();
AzIdP.init()
    .discoveryConfig(discoveryConfig)
    ...
    .build();
```

## Password Grant

If the service supports resource owner password grant, AzIdP4J doesn't support user authentication so needs to configure userPasswordVerifier.

```java
var userPasswordVerifier =
        new UserPasswordVerifier() {
            @Override
            public boolean verify(String username, String password) {
                return switch (username) {
                    case "user1" -> password.equals("password1");
                    case "user2" -> password.equals("password2");
                    case "user3" -> password.equals("password3");
                    default -> false;
                };
            }
        };
AzIdP.init()
  .userPasswordVerifier(userPasswordVerifier)
  ...
  .build();
```