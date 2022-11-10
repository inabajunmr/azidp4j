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

var discovery =
        DiscoveryConfig.builder()
                .authorizationEndpoint("https://example.com/authorize")
                .tokenEndpoint("https://example.com/token")
                .userInfoEndpoint("https://example.com/userinfo")
                .clientRegistrationEndpoint("https://example.com/client")
                .clientConfigurationEndpointPattern(
                        "https://example.com/client/{CLIENT_ID}")
                .jwksEndpoint("https://example.com/jwks")
                .build();
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
        .scopesSupported(Set.of("openid"))
        .discovery(discovery).build();
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

## Sample applications

* [with com.sun.net.httpserver.HTTPServer](azidp4j-httpserver-sample/README.md)
* [with Spring Boot and Spring Security](azidp4j-spring-security-sample/README.md)