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
Show details at Java inline comments. 

#### [by Spring Security] Login

User login is served by Spring Security.
User store is [in Memory](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/SecurityConfiguration.java#L65) and signup is unsupported.
Watch the [SecurityConfiguration](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/SecurityConfiguration.java#L48) also.

#### Consent

Consent page is served at [ConsentHandler](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/ConsentHandler.java#L28).
User consents scopes, [InMemoryUserConsentStore](https://github.com/inabajunmr/azidp4j/blob/main/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/ConsentHandler.java#L43) stores consented scopes.

#### [by azidp4j] Token Endpoint

```
POST /token
```

Token Endpoint is implemented at [TokenEndpointHandler](https://github.com/inabajunmr/azidp4j/blob/d3acca4b9c09a77d0ca05a8389a94e53135978d4/azidp4j-spring-security-sample/src/main/java/org/azidp4j/springsecuritysample/handler/TokenEndpointHandler.java#L35).
Show details at Java inline comments.

// TODO add inline comments

#### Client Registration Endpoint

#### UserInfo Endpoint

#### JWKs Endpoint

#### Introspection Endpoint

#### Revocation Endpoint

### Authentication/Authorization

#### Client authentication

#### Bearer Token Introspection

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
