# Client Registration

AzIdP4J supports client registration.
Service can register new client by AzIdp#registerClient and delete client by AzIdp#deleteClient.
But AzIdP4J doesn't manage client authentication or token authorization so the service may implement it by itself.

These methods return [ClientRegistrationResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/client/response/ClientRegistrationResponse.java) or [ClientDeleteResponse](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/client/response/ClientDeleteResponse.java).
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

// If service required authentication or authorization, it must process before AzIdp#readClient.
azIdP.readClient(response.get("client_id"));

// If service required authentication or authorization, it must process before AzIdp#deleteClient.
azIdP.deleteClient(response.get("client_id"));
```

## Specification

* [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
* [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)

### Samples

* [Basic OAuth 2.0 Authorization Server](https://github.com/inabajunmr/azidp4j/blob/cdd6ca73797efb7642e970f03d53ddc867dfe323/azidp4j/src/test/java/org/azidp4j/sample/OAuth2Sample.java#L43-L60)
* [Basic OpenID Connect Identity Provider](https://github.com/inabajunmr/azidp4j/blob/df3e550359b75823f489b3c6f1571b59ef59552b/azidp4j/src/test/java/org/azidp4j/sample/OidcSample.java#L58-L75)

## Client parameters

### Request

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

### Response

All Requested metadata with following parameters are returned.

| name | description | specification |
| --- | --- | --- |
| client_id | Client identifier. Key of  ClientStore. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| client_secret | Client secret for client authetnication. But AzIdP4J doesn't support client authentication. The value is refered via ClientStore. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| registration_access_token | Access token for client configuration endpoint. But AzIdP4J doesn't support authorization. The token can be introspected by AzIdP#introspect. The value is returend only clientConfigurationEndpointIssuer configured. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |
| registration_client_uri | Client configuration endpoint. But AzIdP4J doesn't support web endpoint. The value is decided by clientConfigurationEndpointIssuer. The value is returend only clientConfigurationEndpointIssuer configured. | * [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc7591)<br>* [OIDC](https://openid.net/specs/openid-connect-registration-1_0.html) |

## Using Client

When the service wants to use client for like client authentication, service can find the registered client via [ClientStore](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j/src/main/java/org/azidp4j/client/ClientStore.java).
```
var response = azIdP.registerClient(client);
var client = clientStore.find(response.get("client_id"));
// using client for service specific requirements
```
