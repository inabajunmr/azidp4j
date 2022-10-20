package org.azidp4j.springsecuritysample;

import static org.springframework.security.config.Customizer.withDefaults;

import org.azidp4j.springsecuritysample.user.UserInfo;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired BearerTokenBodyAuthenticationFilter bearerTokenBodyAuthenticationFilter;

    @Autowired UserStore userStore;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.authorizeHttpRequests(
                        (authorize) ->
                                authorize
                                        .mvcMatchers(
                                                "/authorize",
                                                "/token",
                                                "/client",
                                                "/.well-known/jwks.json",
                                                "/.well-known/openid-configuration",
                                                "/introspect",
                                                "/revoke")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated())
                .httpBasic(withDefaults())
                .formLogin(withDefaults())
                .oauth2ResourceServer()
                .opaqueToken();
        http.httpBasic().disable();
        http.csrf()
                .ignoringAntMatchers(
                        "/authorize", "/token", "/client", "/userinfo", "/introspect", "/revoke");
        // @formatter:on

        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector introspector(AccessTokenService accessTokenService) {
        return new InternalOpaqueTokenIntrospector(accessTokenService);
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user1 =
                User.withDefaultPasswordEncoder()
                        .username("user1")
                        .password("password1")
                        .roles("USER")
                        .build();
        var userInfo1 = new UserInfo();
        userInfo1.put("sub", user1.getUsername());
        userStore.save(userInfo1);
        UserDetails user2 =
                User.withDefaultPasswordEncoder()
                        .username("user2")
                        .password("password2")
                        .roles("USER")
                        .build();
        var userInfo2 = new UserInfo();
        userInfo2.put("sub", user2.getUsername());
        userStore.save(userInfo2);
        UserDetails user3 =
                User.withDefaultPasswordEncoder()
                        .username("user3")
                        .password("password3")
                        .roles("USER")
                        .build();
        var userInfo3 = new UserInfo();
        userInfo3.put("sub", user3.getUsername());
        userStore.save(userInfo3);
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }
}
