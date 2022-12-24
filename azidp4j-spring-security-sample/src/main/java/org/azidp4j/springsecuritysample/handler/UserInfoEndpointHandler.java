package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import java.util.stream.Collectors;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserInfoEndpointHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoEndpointHandler.class);

    @Autowired UserStore userStore;

    /**
     * @see <a
     *     href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
     */
    @RequestMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo() {
        LOGGER.info(UserInfoEndpointHandler.class.getName());

        // The endpoint requires authorization by bearer token.
        // Authorization is supported by Spring Security.
        // ref. org.azidp4j.springsecuritysample.SecurityConfiguration
        // ref. org.azidp4j.springsecuritysample.authentication.InternalOpaqueTokenIntrospector
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof BearerTokenAuthentication) {
            var scopes =
                    auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(a -> a.matches("^SCOPE_.*"))
                            .map(a -> a.replace("SCOPE_", ""))
                            .collect(Collectors.toSet());

            // `openid` scope is required for the endpoint.
            if (scopes.contains("openid")) {
                // IdP can get username as sub from introspection.
                var username = auth.getName();
                // azidp4j doesn't support UserInfo endpoint so construct response by itself.
                return ResponseEntity.status(200)
                        .body(userStore.find(username).filterByScopes(scopes));
            } else {
                return ResponseEntity.status(401).build();
            }
        } else {
            return ResponseEntity.status(401).build();
        }
    }
}
