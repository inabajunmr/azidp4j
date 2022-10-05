package org.azidp4j.springsecuritysample.handler;

import java.util.Map;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoEndpointHandler {

    @Autowired AzIdP azIdP;

    @Autowired UserStore userStore;

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof BearerTokenAuthentication) {
            var scopes =
                    auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(a -> a.matches("^SCOPE_.*"))
                            .collect(Collectors.toSet());
            if (scopes.contains("SCOPE_openid")) {
                var username = auth.getName();
                return ResponseEntity.status(200).body(userStore.find(username));
            } else {
                return ResponseEntity.status(401).build();
            }
        } else {
            return ResponseEntity.status(401).build();
        }
    }
}
