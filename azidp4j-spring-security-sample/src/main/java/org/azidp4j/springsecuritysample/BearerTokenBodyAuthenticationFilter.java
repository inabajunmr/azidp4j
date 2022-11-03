package org.azidp4j.springsecuritysample;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** RFC6750 */
@Component
public class BearerTokenBodyAuthenticationFilter extends OncePerRequestFilter {

    @Autowired AccessTokenService accessTokenService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!request.getParameterMap().containsKey("access_token")) {
            filterChain.doFilter(request, response);
        } else {
            if (request.getHeader("Content-Type").equals("application/x-www-form-urlencoded")) {
                filterChain.doFilter(request, response);
                return;
            }
            if (!request.getMethod().equals("POST")) {
                filterChain.doFilter(request, response);
                return;
            }
            var at =
                    accessTokenService.introspect(request.getParameterMap().get("access_token")[0]);
            if (at.isEmpty()) {
                filterChain.doFilter(request, response);
            } else {
                var principal =
                        new OAuth2IntrospectionAuthenticatedPrincipal(
                                at.get().getSub(),
                                Map.of("test", "test"),
                                Arrays.stream(at.get().getScope().split(" "))
                                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                                        .collect(Collectors.toSet()));
                filterChain.doFilter(request, response);
                var authentication =
                        new BearerTokenAuthentication(
                                principal,
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        at.get().getToken(),
                                        null,
                                        Instant.ofEpochSecond(at.get().getExpiresAtEpochSec())),
                                principal.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
            }
        }
    }
}
