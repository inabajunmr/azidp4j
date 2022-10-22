package org.azidp4j.springsecuritysample;

import java.io.IOException;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.azidp4j.springsecuritysample.authentication.ClientAuthenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ClientAuthenticationFilter extends OncePerRequestFilter {

    @Autowired ClientAuthenticator clientAuthenticator;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        request.getParameterMap();
        var a = new LinkedMultiValueMap<String, String>();
        request.getParameterMap().forEach((k, v) -> a.add(k, v[0]));
        var clientOpt = clientAuthenticator.authenticateClient(request, a);
        if (clientOpt.isPresent()) {
            var client = clientOpt.get();
            SecurityContextHolder.getContext()
                    .setAuthentication(
                            new UsernamePasswordAuthenticationToken(
                                    client.clientId,
                                    client.clientSecret,
                                    Set.of(new SimpleGrantedAuthority("CLIENT"))));
            filterChain.doFilter(request, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
