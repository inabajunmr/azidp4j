# azidp4j-spring-security-sample

This implementation is Authorization Server and Identity Provider by azidp4j integrated with Spring Boot and Spring Security.

## bootRun

```
./gradlew bootRun
```

After bootRun, application print following information to STDIN.

* Initialized Client
* Authorization Request Sample
* Token Request Sample

```
{grant_types=[refresh_token, implicit, client_credentials, authorization_code], application_type=web, scope=scope1 scope2 openid client, registration_client_uri=http://localhost:8080/client/1289972c-c33e-4c75-a044-98cbbc5094ea, require_auth_time=false, client_secret=e84e38a6-8742-4380-bcdf-f6bd163d3405, redirect_uris=[https://client.example.com/callback2, https://client.example.com/callback1], registration_access_token=eb8c992c-0207-4726-ae74-6e1cec869f3c, client_id=1289972c-c33e-4c75-a044-98cbbc5094ea, token_endpoint_auth_method=client_secret_basic, response_types=[code, id_token, token], id_token_signed_response_alg=RS256}
http://localhost:8080/authorize?response_type=code&client_id=1289972c-c33e-4c75-a044-98cbbc5094ea&redirect_uri=http%3A%2F%2Fclient.example.com%2Fcallback1&scope=scope1
curl -X POST -u 1289972c-c33e-4c75-a044-98cbbc5094ea:e84e38a6-8742-4380-bcdf-f6bd163d3405 -d 'grant_type=authorization_code' -d 'redirect_uri=http://client.example.com/callback1' -d 'code=xxx' http://localhost:8080token
```

## Implementation

### Initializations

The application initialize AzIdP at [AzIdPConfiguration](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/AzIdPConfiguration.java#L35) as Spring Bean.

### Endpoints

#### [by azidp4j] Authorization Endpoint 

```
GET /authorize
```

Authorization Endpoint is implemented at [AuthorizationEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/AuthorizationEndpointHandler.java#L38).
Show details at inline comments. 

#### [by Spring Security] Login

User login is served by Spring Security.
User store is [in Memory](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/SecurityConfiguration.java#L65) and signup is unsupported.
Watch the [SecurityConfiguration](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/SecurityConfiguration.java#L48) also.

Following tables are initial creted users.

| username | password  |
|----------|-----------|
| user1    | password1 |
| user2    | password2 |
| user3    | password3 |

#### Consent

Consent page is served at [ConsentHandler](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/ConsentHandler.java#L28).
User consents scopes, [InMemoryUserConsentStore](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/ConsentHandler.java#L43) stores consented scopes.

#### [by azidp4j] Token Endpoint

```
POST /token
```

Token Endpoint is implemented at [TokenEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/TokenEndpointHandler.java#L35).
Show details at inline comments.

#### [by azidp4j] Client Registration Endpoint

```
POST /client
DELETE /client/${client_id}
```

Client Registration Endpoint is implemented at [DynamicClientRegistrationEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/DynamicClientRegistrationEndpointHandler.java#L16).
Show details at inline comments.

The Controller has endpoint for delete client also.
Client deletion requires bearer token that issued at client registration.
The implementation uses Spring Security for introspect bearer token.
Show details at inline comments.

#### UserInfo Endpoint

```
GET or POST /userinfo
```

azidp4j doesn't support UserInfo endpoint so the implementation supports it by itself.
The endpoint is implemented at [UserInfoEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/UserInfoEndpointHandler.java#L16).

Show details at inline comments.

#### JWKs Endpoint

```
GET /.well-known/jwks.json
```

azidp4j doesn't support JWKs endpoint.
[JwksEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/JwksEndpointHandler.java#L12) just returns JWKSet.

#### [by azidp4j] Discovery Endpoint

```
GET /.well-known/openid-configuration
```

Discovery Endpoint is implemented at [DiscoveryEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/DiscoveryEndpointHandler.java).
azidp4j publishes metadata by configuration.

#### [by azidp4j] Introspection Endpoint

Introspection Endpoint is implemented at [IntrospectionEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/IntrospectionEndpointHandler.java#L22).
Show details at inline comments.

#### [by azidp4j] Revocation Endpoint

Revocation Endpoint is implemented at [RevocationHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/RevocationHandler.java#L22).
Show details at inline comments.

### Authentication/Authorization

Some endpoints require authentication or authorization.

#### Client authentication

Following endpoints always require client authentication.

* Revocation Endpoint
* Introspection Endpoint

Following endpoints require client authentication when client is confidential.

* Token Endpoint

azidp4j doesn't support client authentication so application needs to implement it.
This sample's client authentication is implemented at [ClientAuthenticationFilter](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/authentication/ClientAuthenticationFilter.java) and [ClientAuthenticator](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/authentication/ClientAuthenticator.java).

#### Bearer Token authorization

Following endpoints always require client authentication.

* UserInfo Endpoint
* Client Deletion Endpoint

azidp4j support token introspection.
The implementation use Spring Security Resource Server but Token Introspection is implemented by itself.

Spring Security Resource Server configuration is defined at [SecurityConfiguration](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/SecurityConfiguration.java#L24).
Introspection is implemented at [InternalOpaqueTokenIntrospector](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/authentication/InternalOpaqueTokenIntrospector.java#L18).

## Deploy for conformance test

This application is used for conformance test also.

### Docker Build

```
./gradlew bootBuildImage --imageName=azidp4j/spring-security-sample
```

### Push ECR

```
aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/f8x3d3l2
```

```
VERSION=v21
docker tag azidp4j/spring-security-sample:latest public.ecr.aws/f8x3d3l2/azidp4j-spring-security-sample:${VERSION}
docker push public.ecr.aws/f8x3d3l2/azidp4j-spring-security-sample:${VERSION}
```
