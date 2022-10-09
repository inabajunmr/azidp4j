package org.azidp4j.springsecuritysample;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

public class InternalOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final AccessTokenStore accessTokenStore;

    public InternalOpaqueTokenIntrospector(AccessTokenStore accessTokenStore) {
        this.accessTokenStore = accessTokenStore;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        var at = accessTokenStore.find(token);
        if (at == null) {
            throw new BadOpaqueTokenException("Provided token isn't active");
        }
        if (at.getExpiresAtEpochSec() < Instant.now().getEpochSecond()) {
            throw new BadOpaqueTokenException("Provided token is expired");
        }
        return new OAuth2IntrospectionAuthenticatedPrincipal(
                at.getSub(),
                Map.of("test", "test"),
                Arrays.stream(at.getScope().split(" "))
                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                        .collect(Collectors.toSet()));
    }
}