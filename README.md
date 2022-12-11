# [alpha] AzIdP4J

[![Maven Central](https://img.shields.io/maven-central/v/io.github.inabajunmr/AzIdP4J.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22io.github.inabajunmr%22%20AND%20a:%22AzIdP4J%22)
![GitHub Actions](https://github.com/inabajunmr/azidp4j/actions/workflows/main.yml/badge.svg)

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

### Installation

[Maven Repository](https://mvnrepository.com/artifact/io.github.inabajunmr/AzIdP4J/0.0.0-alpha+002)

#### Maven

```
<dependency>
    <groupId>io.github.inabajunmr</groupId>
    <artifactId>AzIdP4J</artifactId>
    <version>0.0.0-alpha+002</version>
</dependency>
```

#### Gradle

```
implementation group: 'io.github.inabajunmr', name: 'AzIdP4J', version: '0.0.0-alpha+002'
```

#### Gralde(Kotlin)

```
implementation("io.github.inabajunmr:AzIdP4J:0.0.0-alpha+002")
```

### Configuration

```java
var rs256 =
        new RSAKeyGenerator(2048)
                .keyID("rs256key")
                .algorithm(new Algorithm("RS256"))
                .generate();
var jwks = new JWKSet(rs256);
var azidp =
        AzIdP.initInMemory()
                .jwkSet(jwks)
                .idTokenKidSupplier((alg) -> jwks.getKeys().get(0).getKeyID())
                .issuer("https://idp.example.com")
                .grantTypesSupported(
                        Set.of(GrantType.authorization_code, GrantType.client_credentials))
                .scopesSupported(Set.of("openid", "item:read"))
                .customScopeAudienceMapper((scope) -> Set.of("https://rs.example.com"))
                .build();
```

### Client Registration

```java
var clientRequest =
        new ClientRequest(
                Map.of(
                        "redirect_uris",
                        Set.of("https://client.example.com/callback"),
                        "grant_types",
                        Set.of("authorization_code", "client_credentials"),
                        "scope",
                        "openid item:read"));
var clientResponse = azidp.registerClient(clientRequest);
System.out.println(clientResponse.body);
// {grant_types=[client_credentials, authorization_code], application_type=web, scope=openid item:read, require_auth_time=false, client_secret=f13b412b-f5b6-4432-9764-ffa891ef5ae9, redirect_uris=[https://client.example.com/callback], client_id=b9b60f89-97f3-4537-9604-a638d58df4d4, token_endpoint_auth_method=client_secret_basic, response_types=[code], id_token_signed_response_alg=RS256}
```

### Authorization Endpoint

```java
// This is constructed via http request generally.
var authorizationRequestQueryParameterMap =
        Map.of(
                "scope", "openid item:read",
                "response_type", "code",
                "client_id", clientResponse.body.get("client_id").toString(),
                "redirect_uri", "https://client.example.com/callback",
                "state", "abc",
                "nonce", "xyz");
var authorizationRequest =
        new AuthorizationRequest(
                "inabajun", // authenticated user
                Instant.now().getEpochSecond(),
                Set.of("openid", "item:read"),
                authorizationRequestQueryParameterMap);
var authorizationResponse = azidp.authorize(authorizationRequest);
System.out.println(authorizationResponse.redirect.redirectTo);
// https://client.example.com/callback?code=890d9cca-11a2-47b8-b879-1f584fdb0354&state=abc
```

### Token Endpoint
```java
var code = authorizationResponse.redirect.redirectTo.replaceAll(".*code=([^&]+).*", "$1");
var tokenRequest =
        new TokenRequest(
                clientResponse.body.get("client_id").toString(),
                // This is constructed via http request generally.
                Map.of(
                        "code",
                        code,
                        "grant_type",
                        "authorization_code",
                        "redirect_uri",
                        "https://client.example.com/callback"));
var tokenResponse = azidp.issueToken(tokenRequest);
System.out.println(tokenResponse.body);
// {access_token=2100bccf-6428-435d-bbac-6849bf1c28fc, refresh_token=50ecc0bd-a48a-4df4-a62e-768896ba4f24, scope=openid item:read, id_token=eyJraWQiOiJyczI1NmtleSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiZHZDcXhOQ3lNNG9kdWhfS1EwU0trZyIsInN1YiI6ImluYWJhanVuIiwiYXVkIjoiNGUzMWViZDItNTZmNy00MDM0LWIwNjEtNjcyNGEzNzUwYTEwIiwiYXpwIjoiNGUzMWViZDItNTZmNy00MDM0LWIwNjEtNjcyNGEzNzUwYTEwIiwiYXV0aF90aW1lIjoxNjY4OTMzNDU5LCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImV4cCI6MTY2ODkzNDA1OSwiaWF0IjoxNjY4OTMzNDU5LCJub25jZSI6Inh5eiIsImp0aSI6ImY0YjhlMGUyLWIwMTktNDI1ZC1hMmRkLTdmZWUwNzFmYzM3NSJ9.n-YJnhe-NlQdzydRoPq2I0bSsWD-iyx3DHYToZvmUHnncgcpjEvNA2QGsWnSPShJickAAh3sJ53d4LenMJDpGzhJbeAYq3Fh6UgC_NsH5yYimbCFg1i6nVySV-ntbC6tmvAz1Ey1QsIHmZO5azGzbIbjm47jfl-NhZHbH4pg7lBbQ3_KmOy3kfmOil14Qyz8sNrT4LX_5T4nK3YjrPWDsCYlGm_cXHL5zwPnwZkWifU-D6ro-j9yK3E30kQ2qEsj_bhjzcpLem7-y67EfzuJTAhQbxPaasToh_lcPXaXS9krVodU1pPkk6aFs4IDurbqsoUGZH28YEOW4oowbSoyyw, state=abc, token_type=bearer, expires_in=600}
```

## Documentation

* [Configuration](docs/config.md)
  * How to initialize AzIdP4J
* [Endpoint implementations](docs/endpoint-implementations.md)
  * How to implement endpoints like authorization endpoint or token endpoint
* [Client Registration](docs/client-registration.md)
  * How to implement endpoint for client registration

## Sample applications

* [with Spring Boot and Spring Security](azidp4j-spring-security-sample)
* [with com.sun.net.httpserver.HTTPServer](azidp4j-httpserver-sample)

## Release

### gradle.properties

```
signing.keyId=xxx
signing.password=xxx
signing.secretKeyRingFile=/Users/xxx/.gnupg/xxx

sonatypeUsername=xxx
sonatypePassword=xxx
```

### version

at azidp4j/build.gradle.kts version

### publish

```
./gradlew azidp4j:publish
```

### release

https://s01.oss.sonatype.org/