package org.azidp4j.springsecuritysample.authentication;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.introspection.request.IntrospectionRequest;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

@Component
@Primary
public class InternalOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final AzIdP azIdP;

    public InternalOpaqueTokenIntrospector(AzIdP azIdP) {
        this.azIdP = azIdP;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        // TODO using spring impl
        var res =
                azIdP.introspect(
                        new IntrospectionRequest(
                                Map.of("token", token, "token_type_hint", "access_token")));
        if (res.status != 200) {
            throw new BadOpaqueTokenException("Provided token isn't active");
        }
        if (res.body.get("active") instanceof Boolean active && active) {
            return new OAuth2IntrospectionAuthenticatedPrincipal(
                    res.body.get("sub").toString(),
                    Map.of("test", "test"),
                    Arrays.stream(res.body.get("scope").toString().split(" "))
                            .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                            .collect(Collectors.toSet()));
        }
        throw new BadOpaqueTokenException("Provided token isn't active");
    }
}
