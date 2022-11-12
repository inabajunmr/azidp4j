# [wip] azidp4j

azidp4j is library for Java OAuth 2.0 Authorization Server & OpenID Connect Identity Provider.

## Supported Functions

### Supported specifications

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  * azidp4j doesn't support
    * UserInfo endpoint
    * ID Token claims
      * azidp4j issue ID Token that has only sub
    * Request object
    * PPID
    * Encrypted ID Token
    * ...
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
* [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
* [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
* [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)

### azidp4j doesn't support

Application needs to implement...

* Web application server
* Persistence
* Client authentication
* User management and authentication

## Quickstart

### Initialization

```java
var rs256 =
        new RSAKeyGenerator(2048)
                .keyID("rs256key")
                .algorithm(new Algorithm("RS256"))
                .generate();
var azIdP = AzIdP.initInMemory()
        .issuer("https://example.com")
        .jwkSet(new JWKSet(List.of(rs256)))
        .idTokenKidSupplier((alg) -> rs256.getKeyID())
        .staticScopeAudienceMapper("audience")
        .scopesSupported(Set.of("openid")).build();
```

### Authorization Endpoint

```java
var authenticatedUserName = 'inabajun';
var authTime = 1667152734;
var consentedScopes = Set.of("user:read");
var params = authorization request parameters from your web application.
var authzReq =
        new AuthorizationRequest(
                authenticatedUserName,
                authTime,
                consentedScopes,
                params);
var response = azIdP.authorize(authzReq);
switch (response.next) {
    case redirect -> {
        // TODO redirect to response.redirect.redirectTo
    }
    case errorPage -> {
        // TODO show error page
    }
    case additionalPage -> {
        switch (additionalPage.prompt) {
        case login -> {
            // TODO show login page
        }
        case consent -> {
            // TODO show consent page
            // construct consent page by additionalPage.scope and additionalPage.clientId
        }
        case select_account -> {
            // TODO show select account page
        }
    }
}
```

### Token Endpoint
```java
// you need to implement client authentication
var authenticatedClientId = client id from your implementation;
var params = token request parameters from your web application.
var response =
        azIdP.issueToken(new TokenRequest(authenticatedClientId, params));
// TODO construct http response by response.status and response.body
```

## Documentation 

### Initializations

All of azidp4j functions are defined at [AzIdP]().
For initialize AzIdP instance, use AzIdP#init or AzIdp#initInMemory(for using inMemory stores), AzIdp#initJwt(for using jwt tokens).

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

#### Fields

<!-- https://docs.google.com/spreadsheets/d/1MulCF7UbLvtroGYlv-U1cIPEJrRmWptGpmpfrC9gSFM/edit#gid=0 -->

name	optional	description	value	example
issuer	required	Identifier of identity provider. The value is used for like JWT iss claim, introspection result.	See OpenID Provider Metadata	https://idp.example.com
jwkSet	openid required	JwkSet is keys for signing token like ID Token. The parameter is required when using openid scope.	See [Nimbus JOSE documentation](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/2.13.1/com/nimbusds/jose/jwk/JWKSet.html).	see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/AzIdPConfiguration.java#L142)
idTokenKidSupplier	openid required	For choosing which JWK using. The parameter is required when using openid scope.		see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/IdTokenKidSupplier.java#L8)
scopesSupported	required	Supported scopes for the service. When supporting OpenID Connect, requires `openid` scope.		Set.of("openid", "user:read")
defaultScopes	optional	Scopes for no scope authorization request.		Set.of("openid", "user:read")
authorizationCodeExpiration	optional	Expiration time for authorization code. Default is 1min.		Duration.ofDays(1)
accessTokenExpiration	optional	Expiration time for access token. Default is 10min.		Duration.ofDays(1)
idTokenExpiration	optional	Expiration time for id token. Default is 10min.		Duration.ofDays(1)
refreshTokenExpiration	optional	Expiration time for refresh token Default is 1day.		Duration.ofDays(1)
grantTypesSupported	optional	Supported grant types by Authorization Server. Default variables are `authorization_code` and `implicit`.	`authorization_code` / `implicit` / `password` / `client_credential` / `refresh_token`	Set.of(GrantType.authorization_code)
responseTypesSupported	optional	Supported response types by Authorization Server.	`code` / `token` / `id_token` / `none`	Set.of(Set.of(ResponseType.code), Set.of(ResponseType.token)
responseModesSupported	optional	Supported response modes by Authorization Server.	`query` / `fragment`	Set.of(ResponseMode.query)
clientStore	required	See [ClientStore](#clientstore).		
clientValidator	optional	See [ClientValidator](#clientvalidator).		
authorizationCodeService	optional	See [Token Stores Configuration](token-stores-configuration). When supporting `authorization_code grant type, the value is required.		
scopeAudienceMapper	required	Mapping scopes to audience. Using for introspection result and JWT aud claim except for ID Token.		scope -> Set.of("rs.example.com")
accessTokenService	required	See [Token Stores Configuration](token-stores-configuration).		
refreshTokenService	optional	See [Token Stores Configuration](token-stores-configuration). When supporting `refresh_token` grant type, the value is required.		
discoveryConfig	required	See [Discovery Configuration](#discovery-configuration).		
userPasswordVerifier	optional	See [Password Grant](#password-grant).  When supporting `password` grant type, the value is required.

#### ClientStore

AzIdp4J doesn't provide client persistence except for in-memory implementation.
When application want to persist client information on another datastore, application needs to implement ClientStore interface by themselves and configure it like following example.

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

#### ClientValidator

AzIdP4J validate client while client registration but service-specific restriction can be injected by ClientValidator.
If your service want to accept only token_endpoint_auth_method=client_secret_basic, define like following example.

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

#### Token Stores Configuration

AzIdp4J provides in-memory or JWT token services.
But former isn't practical and later has restriction that can't support token revocation or.
If service want to store tokens on service specific data store, you can use your service specific implementation.

AzIdp4J has the following services.
See these class's javadoc for implementation requirement.

* AuthorizationCodeService
* AccessTokenService
* RefreshTokenService

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

#### Discovery Configuration

If the service want to use AzIdp#discovery for Discovery Endpoint, needs to configure discoveryConfig.
DiscoveryConfigBuilder the class for DiscoveryConfig initiation.

```java
var discoveryConfig =
        DiscoveryConfig.builder()
                .authorizationEndpoint(endpoint + "/authorize")
                .tokenEndpoint(endpoint + "/token")
                .jwksEndpoint(endpoint + "/.well-known/jwks.json")
                .clientRegistrationEndpoint(endpoint + "/client")
                .userInfoEndpoint(endpoint + "/userinfo")
                .build();
AzIdP.init()
    .discoveryConfig(discoveryConfig)
    ...
    .build();
```

Service can only specify supported endpoint.
If the service only supports authorization endpoint and token endpoint, configuration will be like following example.

```java
var discoveryConfig =
        DiscoveryConfig.builder()
                .authorizationEndpoint(endpoint + "/authorize")
                .tokenEndpoint(endpoint + "/token")
                .build();
AzIdP.init()
    .discoveryConfig(discoveryConfig)
    ...
    .build();
```

#### Password Grant

If service supports resource owner password grant, azidp4j doesn't support user authentication so needs to configure userPasswordVerifier.

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

## Sample applications

* [with Spring Boot and Spring Security](azidp4j-spring-security-sample)
* [with com.sun.net.httpserver.HTTPServer](azidp4j-httpserver-sample)
