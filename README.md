# [wip] AzIdP4J

AzIdP4J is library for Java OAuth 2.0 Authorization Server & OpenID Connect Identity Provider.

## Supported Functions

### Supported specifications

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  * AzIdP4J doesn't support
    * UserInfo endpoint
    * ID Token claims
      * AzIdP4J issue ID Token that has only sub
    * Request object
    * PPID
    * Encrypted ID Token
    * ...
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
* [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
* [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
* [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)

### AzIdP4J doesn't support

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

All of AzIdP4J functions are defined at [AzIdP](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/AzIdP.java).
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

| name | optional | description | value | example |
| --- | --- | --- | --- | --- |
| issuer | required | Identifier of identity provider. The value is used for like JWT iss claim, introspection result. | See OpenID Provider Metadata | https://idp.example.com |
| jwkSet | openid required | JwkSet is keys for signing token like ID Token. The parameter is required when using openid scope. | See [Nimbus JOSE documentation](https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/2.13.1/com/nimbusds/jose/jwk/JWKSet.html). | see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/AzIdPConfiguration.java#L142) |
| idTokenKidSupplier | openid required | For choosing which JWK using. The parameter is required when using openid scope. |  | see [sample implementation](https://github.com/inabajunmr/azidp4j/blob/4e60de6ad7bb534b32c0747945f68edaf837620d/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/IdTokenKidSupplier.java#L8) |
| scopesSupported | required | Supported scopes for the service. When supporting OpenID Connect, requires `openid` scope. |  | Set.of("openid", "user:read") |
| defaultScopes | optional | Scopes for no scope authorization request. |  | Set.of("openid", "user:read") |
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
| discoveryConfig | required | See [Discovery Configuration](#discovery-configuration). |  |  |
| userPasswordVerifier | optional | See [Password Grant](#password-grant).  When supporting `password` grant type, the value is required. |  |  |

#### [ClientStore](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/client/ClientStore.java)

AzIdP4J doesn't provide client persistence except for in-memory implementation.
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

#### [ClientValidator](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J-spring-security-sample/src/main/java/org/AzIdP4J/springsecuritysample/ClientValidator.java)

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

AzIdP4J provides in-memory or JWT token services.
But former isn't practical and later has restriction that can't support token revocation or.
If service want to store tokens on service specific data store, you can use your service specific implementation.

AzIdP4J has the following services.
See these class's javadoc for implementation requirement.

* [AuthorizationCodeService](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/authorize/authorizationcode/AuthorizationCodeService.java)
* [AccessTokenService](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/token/accesstoken/AccessTokenService.java)
* [RefreshTokenService](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/token/refreshtoken/RefreshTokenService.java)

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
[DiscoveryConfigBuilder](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/discovery/DiscoveryConfigBuilder.java) the class for DiscoveryConfig initiation.

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

If service supports resource owner password grant, AzIdP4J doesn't support user authentication so needs to configure userPasswordVerifier.

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

### Authorization Request

AzIdP4J process authorization request by AzIdP#authorize.
But AzIdP4J doesn't manage user authentication and consent so service must implement these function by itself.

#### Specification

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-3.1)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)

#### Request

AzIdP#authorize accept following parameters.

* authenticatedUserId
  * authenticated user who send authorization request. If no user authenticated, specify null. The value will be `sub` claim.
* authTime
  * Last user authenticated time. If no user authenticated, specify null. Epoch sec.
* consentedScope
  * Last user authenticated time. If no user authenticated, specify null.
* queryParameters
  * Authorization request query parameters map.

```java
// When user authenticated
var authenticatedUserName = 'inabajun';
var authTime = 1668270263L;
var consentedScopes = Set.of("openid");
var params = // convert http request query parameters to Map<String, String>;
var authzReq =
        new AuthorizationRequest(
                authenticatedUserName,
                authTime,
                consentedScopes,
                params);
var response = azIdP.authorize(authzReq);

// When no user authenticated
        var params = // convert http request query parameters to Map<String, String>;
        var authzReq = new AuthorizationRequest(null, null, null, params);
        var response = azIdP.authorize(authzReq);
```

#### Response

AzIdP#authorize returns [AuthorizationResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/authorize/response/AuthorizationResponse.java).
AuthorizationResponse#next express service what should do next.

```java
var response = azIdP.authorize(authzReq);
switch (response.next) {
    case redirect -> {
        // redirect to response.redirect.redirectTo;
    }
    case errorPage -> {
        // Error but can't redirect as authorization response.
        // show error page with response.errorPage.errorType
    }
    case additionalPage -> {
        // When authorization request processing needs additional action by additionalPage.prompt.
        // ex. user authentication or request consent.
    }
}
```

Following next parameters are defined.

* redirect
  * service just redirect to `response.redirect.redirectTo`
* errorPage
  * see [errorPage](#error-page)
* additionalPage
  * see [additionalPage](#additional-page)

##### errorPage

When authorization request is something wrong but can't redirect to client, AzIdP#authorize returns `errorPage`.
In this case, `errorPage.errorType` will be set so show error page against each errorType.

##### additionalPage

When AzIdP4J requires additional action like user login, AzIdP#authorize returns `additionalPage`.
The type of additionalPage is defined at `additionalPage.prompt`.

Following types are defined as prompt.

* login
  * Required user login. Leading to login page generally.
* consent
  * Required user consent. Leading to consent page generally.
* select_account
  * Required select user account. Leading to account select page generally.
  * If service doesn't support this, send to error page.

`additionalPage` has following parameters so use them to show these pages.

* display
* clientId
* scope

After additional action, generally redirect to authorization request also.
But when authorization request prompt parameter, same authorization request cause same action loop.
AuthorizationRequest#removePrompt is used for removing prompt parameter to avoid this situation.

```java
switch (response.additionalPage.prompt) {
    case login -> {
        // use this parameters to re-authorization request after login
        var redirectAfterLoginQueryParamters = "authzReq.removePrompt("login").queryParameters()
        // send to login page
        }
    case consent -> {
        // use this parameters to re-authorization request after consent
        var redirectAfterConsentQueryParamters = authzReq.removePrompt("consent").queryParameters()
        // send to consent page
    }
    case select_account -> {
        // use this parameters to re-authorization request after account select
        var redirectAfterAccountSelectQueryParamters = authzReq.removePrompt("select_account").queryParameters()
        // send to login page
    }
```

### Token Request

AzIdP4J process token request by AzIdP#issueToken.
But AzIdP4J doesn't manage client authentication so service must implement it by itself.

#### Specification

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint)
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)

#### Request

AzIdP#issueToken accept following parameters.

* authenticatedClientId
  * Authenticated client that send token request. If no client authenticated, specify null.
* bodyParameters
  * Token request body parameters map.

#### Response

AzIdP#issueToken returns TokenResponse.
[TokenResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/token/response/TokenResponse.java) express http response.

```java
var authenticatedClientId = xxxxxclient;
var authenticatedClientId = // convert http request body parameters to Map<String, Object>;
var tokenReq =
        new TokenRequest(
                authenticatedClientId,
                params);
var response = azIdP.issueToken(tokenReq);
// return http response by response.status and response.body.
```

### Discovery

AzIdP4J issue metadata for discovery endpoint against configuration.
AzIdP#discovery returns metadata as Map<String, Object>.

```java
var metadata = azIdP.discovery();
// return http response by metadata.
```

#### Specification

* [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

### Dynamic Client Registration

AzIdP4J supports client registration.
Service can register new client by AzIdp#registerClient and delete client by AzIdp#deleteClient.
But AzIdP4J doesn't manage client authentication or token authorization so service may implement it by itself.

These methods return [ClientRegistrationResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/client/response/ClientRegistrationResponse.java) or [ClientDeleteResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/client/response/ClientDeleteResponse.java).
These classes express http response.

```java
// If service required authentication or authorization, it must process before AzIdp#registerClient.
var client = new ClientRequest(
        Map.of(
          "redirect_uris",
          Set.of("https://client.example.com/callback"),
          "grant_types",
          Set.of("authorization_code","implicit"),
          "response_types", Set.of("code", "token", "id_token"),
          "scope", "openid",
          "token_endpoint_auth_method", "client_secret_basic",
          "id_token_signed_response_alg", "RS256"));
var response = azIdP.registerClient(client);

// If service required authentication or authorization, it must process before AzIdp#deleteClient.
azIdP.deleteClient(response.get("client_id"));
```

#### Specification

* [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)

#### Client parameters

##### Request

All request parameters are optional.

| name | description | specification |
| --- | --- | --- |
| redirect_uris | AzIdP4J allows only registered redirect_uri of Authorization Request. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| token_endpoint_auth_method | AzIdP4J doesn't support client authentication. The parameter is for only client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| grant_types | AzIdP4J allows only registered grant_type. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| application_type | Just client metadata. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| response_types | AzIdP4J allows only registered response_type of Authorization Request. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| client_name | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| client_uri | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| logo_uri | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| scope | Scopes that client can issue. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591) |
| contacts | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| tos_uri | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| policy_uri | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| jwks_uri | AzIdP4J doesn't use client jwks. It's just for service implementations about like client authentication. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| jwks | AzIdP4J doesn't use client jwks. It's just for service implementations about like client authentication. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| software_id | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| software_version | Just client metadata. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| id_token_signed_response_alg | Signing algorithm of ID Token for the client. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| token_endpoint_auth_signing_alg | AzIdP4J doesn't support client authentication. The parameter is for only client metadata. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| default_max_age | Default max_age for Authorization Request. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| require_auth_time | AzIdP4J always returns auth_time claim. It's just client metadata. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| initiate_login_uri | Just client metadata. | * [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |

##### Response

All Requested metadata with following parameters are returned.

| name | description | specification |
| --- | --- | --- |
| client_id | Client identifier. Key of  ClientStore. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| client_secret | Client secret for client authetnication. But AzIdP4J doesn't support client authentication. The value is refered via ClientStore. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| registration_access_token | Access token for client configuration endpoint. But AzIdP4J doesn't support authorization. The token can be introspected by AzIdP#introspect. The value is returend only clientConfigurationEndpointIssuer configured. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| registration_client_uri | Client configuration endpoint. But AzIdP4J doesn't support web endpoint. The value is decided by clientConfigurationEndpointIssuer. The value is returend only clientConfigurationEndpointIssuer configured. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |

#### Using Client

When service want to use client for like client authentication, service can find registered client via [ClientStore](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/client/ClientStore.java).
```
var response = azIdP.registerClient(client);
var client = clientStore.find(response.get("client_id"));
// using client for service specific requirements
```

### Introspection

AzIdP4J supports introspection request.
But AzIdP4J doesn't manage client authentication or token authorization so service must implement it by itself.

#### Specification

* [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

#### Request

AzIdP#introspect accept following parameters.

* bodyParameters
  * Token request body parameters map.

#### Response

AzIdP#introspect returns [IntrospectionResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/introspection/response/IntrospectionResponse.java).
IntrospectionResponse express http response.

```java
// client authentication or bearer token authorization
var request = new IntrospectionRequest(params);
var response = azIdP.issueToken(request);
// return http response by response.status and response.body.
```

### Revocation

// TODO javadoc of reference clas

AzIdP4J process token revocation request by AzIdP#revoke.
But AzIdP4J doesn't manage client authentication so service must implement it by itself.

#### Specification

* [OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)

#### Request

AzIdP#revoke accept following parameters.

* authenticatedClientId
  * Authenticated client that send token request. If no client authenticated, specify null.
* bodyParameters
  * Token request body parameters map.

#### Response

AzIdP#issueToken returns [RevocationResponse](https://github.com/inabajunmr/AzIdP4J/blob/main/AzIdP4J/src/main/java/org/AzIdP4J/revocation/response/RevocationResponse.java).
RevocationResponse express http response.

```java
var authenticatedClientId = xxxxxclient;
var authenticatedClientId = // convert http request body parameters to Map<String, Object>;
var request =
        new RevocationRequest(
                authenticatedClientId,
                params);
var response = azIdP.revoke(request);
// return http response by response.status and response.body.
```

## Sample applications

* [with Spring Boot and Spring Security](AzIdP4J-spring-security-sample)
* [with com.sun.net.httpserver.HTTPServer](AzIdP4J-httpserver-sample)
