package org.azidp4j.springsecuritysample.authentication;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.azidp4j.AzIdP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** RFC6750 */
@Component
public class BearerTokenBodyAuthenticationFilter extends OncePerRequestFilter {

    @Autowired private InternalOpaqueTokenIntrospector introspector;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // TODO consider https://spring.pleiades.io/spring-security/reference/5.8/servlet/oauth2/resource-server/bearer-tokens.html#_reading_the_bearer_token_from_a_custom_header
        if (!request.getParameterMap().containsKey("access_token")) {
            filterChain.doFilter(request, response);
            return;
        }
        if (request.getHeader("Content-Type").equals("application/x-www-form-urlencoded")) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!request.getMethod().equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }
        var at = request.getParameterMap().get("access_token")[0];
        try {
            var principal = introspector.introspect(at);
            var authentication =
                    new BearerTokenAuthentication(
                            principal,
                            new OAuth2AccessToken(
                                    OAuth2AccessToken.TokenType.BEARER, at, null, null),
                            principal.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (BadOpaqueTokenException e) {
            filterChain.doFilter(request, response);
        }
    }
}
