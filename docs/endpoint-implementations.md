# Endpoint implementations

AzIdP4J provide helper for authorization server and identity provider.
It means AzIdP4J doesn't provide HTTP endpoint directly.
The documentations introduce what type of helper AzIdP4J provide and how to use. 

* [Authorization Request](#authorization-request)
* [Token Request](#token-request)
* [Discovery](#discovery)
* [Introspection](#introspection)
* [Revocation](#revocation)

## Authorization Request

AzIdP4J process authorization request by AzIdP#authorize.
But AzIdP4J doesn't manage user authentication and consent so service must implement these function by itself.

### Specification

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-3.1)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)

### Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L63-L87)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L78-L102)
* [Spring Security Sample](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/AuthorizationEndpointHandler.java#L46)

### Request

AzIdP#authorize accept following parameters.

* authenticatedUserId
    * authenticated user who send authorization request. If no user authenticated, specify null. The value will be `sub` claim.
* authTime
    * Last user authenticated time. If no user authenticated, specify null. Epoch sec.
* consentedScope
    * Last user authenticated time. If no user authenticated, specify null.
* queryParameters
    * Authorization request query parameters map.
    * see [Authorization Request Supported parameters](#authorization-request-supported-parameters)

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

#### Authorization Request Supported parameters

| name | optional | description |
| --- | --- | --- |
| response_type | required | code / token / id_token / code token / code id_token / id_token token / code id_token token |
| client_id | required |  |
| redirect_uri | required | AzIdP4J always requires redirect_uri and requires exactly match against registered. |
| scope | optional | If the value is omitted, AzIdP4J uses defined [defaultScopes](config.md). |
| state | optional |  |
| response_mode | optional | query / fragment |
| nonce | optional | The value is required when response_type contains id_token. |
| prompt | optional | none / login / consent / select_account |
| display | optional | page / popup / touch / wrap |
| max_age | optional |  |
| ui_locales | optional |  |
| code_challenge | optional |  |
| code_challenge_method | optional | S256 / plain |

### Response

AzIdP#authorize returns [AuthorizationResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/authorize/response/AuthorizationResponse.java).
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
    * see [errorPage](#errorpage)
* additionalPage
    * see [additionalPage](#additionalpage)

#### errorPage

When authorization request is something wrong but can't redirect to client, AzIdP#authorize returns `errorPage`.
In this case, `errorPage.errorType` will be set so show error page against each errorType.

#### additionalPage

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

## Token Request

AzIdP4J process token request by AzIdP#issueToken.
But AzIdP4J doesn't manage client authentication so service must implement it by itself.

### Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L99-L113)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L114-L133)

### Specification

* [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint)
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)

### Request

AzIdP#issueToken accept following parameters.

* authenticatedClientId
  * Authenticated client that send token request. If no client authenticated, specify null.
* bodyParameters
  * Token request body parameters map.
  * see [Token Request Supported parameters](#token-request-supported-parameters)

#### Token Request Supported parameters

##### Authorization Code Grant

| name | optional | description |
| --- | --- | --- |
| code | required |  |
| grant_type | required | `authorization_code` |
| redirect_uri | required |  |
| client_id | optional | required when authenticatedClientId is not specified. |
| code_verifier | optional |  |

##### Resource Owner Password Grant

| name | optional | description |
| --- | --- | --- |
| grant_type | required | `password` |
| scope | optional |  |
| username | required |  |
| password | required |  |

##### Client Credentials Grant

| name | optional | description |
| --- | --- | --- |
| grant_type | required | `client_credentials` |
| scope | optional |  |

##### Token Refresh

| name | optional | description |
| --- | --- | --- |
| grant_type | required | `refresh_token` |
| refresh_token | optional |  |
| scope | optional |  |

### Response

AzIdP#issueToken returns TokenResponse.
[TokenResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/token/response/TokenResponse.java) express http response.

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

## Discovery

AzIdP4J issue metadata for discovery endpoint against configuration.
AzIdP#discovery returns metadata as Map<String, Object>.

```java
var metadata = azIdP.discovery();
// return http response by metadata.
```

### Specification

* [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Introspection

AzIdP4J supports introspection request.
But AzIdP4J doesn't manage client authentication or token authorization so service must implement it by itself.

### Specification

* [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)

### Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L133-L139)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L150-L156)

### Request

AzIdP#introspect accept following parameters.

* bodyParameters
  * Token request body parameters map.
  * see [Introspection Request Supported parameters](#introspection-request-supported-parameters)

#### Introspection Request Supported parameters

| name | optional | description |
| --- | --- | --- |
| token | required |  |
| token_type_hint | optional |  |

### Response

AzIdP#introspect returns [IntrospectionResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/introspection/response/IntrospectionResponse.java).
IntrospectionResponse express http response.

```java
// client authentication or bearer token authorization
var request = new IntrospectionRequest(params);
var response = azIdP.issueToken(request);
// return http response by response.status and response.body.
```

## Revocation

AzIdP4J process token revocation request by AzIdP#revoke.
But AzIdP4J doesn't manage client authentication so service must implement it by itself.

### Specification

* [OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)

### Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L145-L157)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L162-L174)

### Request

AzIdP#revoke accept following parameters.

* authenticatedClientId
  * Authenticated client that send token request. If no client authenticated, specify null.
* bodyParameters
  * Token request body parameters map.
  * see [Revocation Request Supported parameters](#revocation-request-supported-parameters)

#### Revocation Request Supported parameters

| name | optional | description |
| --- | --- | --- |
| token | required |  |
| token_type_hint | optional |  |

### Response

AzIdP#issueToken returns [RevocationResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/revocation/response/RevocationResponse.java).
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