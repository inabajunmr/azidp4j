package org.azidp4j.springsecuritysample;

import static org.springframework.security.config.Customizer.withDefaults;

import java.time.Instant;
import java.util.Map;
import org.azidp4j.AzIdP;
import org.azidp4j.springsecuritysample.authentication.InternalOpaqueTokenIntrospector;
import org.azidp4j.springsecuritysample.user.UserInfo;
import org.azidp4j.springsecuritysample.user.UserStore;
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

    @Autowired UserStore userStore;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        var resolver = new OIDCConformanceTestBearerTokenResolver();
        resolver.setAllowFormEncodedBodyParameter(true);
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
                .formLogin((form) -> form.loginPage("/login").permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2.bearerTokenResolver(resolver).opaqueToken());
        http.httpBasic().disable();
        http.csrf()
                .ignoringAntMatchers(
                        "/authorize", "/token", "/client", "/userinfo", "/introspect", "/revoke");
        // @formatter:on

        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector introspector(AzIdP azIdP) {
        return new InternalOpaqueTokenIntrospector(azIdP);
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user1 =
                User.withDefaultPasswordEncoder()
                        .username("user1")
                        .password("password1")
                        .roles("USER")
                        .build();
        userStore.save(userinfo(user1));
        UserDetails user2 =
                User.withDefaultPasswordEncoder()
                        .username("user2")
                        .password("password2")
                        .roles("USER")
                        .build();
        userStore.save(userinfo(user2));
        UserDetails user3 =
                User.withDefaultPasswordEncoder()
                        .username("user3")
                        .password("password3")
                        .roles("USER")
                        .build();
        userStore.save(userinfo(user3));
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }

    private UserInfo userinfo(UserDetails userDetails) {
        var userInfo = new UserInfo();
        userInfo.put("sub", userDetails.getUsername());
        userInfo.put("name", userDetails.getUsername());
        userInfo.put("given_name", userDetails.getUsername() + "given_name");
        userInfo.put("family_name", userDetails.getUsername() + "family_name");
        userInfo.put("middle_name", userDetails.getUsername() + "middle_name");
        userInfo.put("nickname", userDetails.getUsername() + "nickname");
        userInfo.put("preferred_username", userDetails.getUsername() + "preferred_username");
        userInfo.put("profile", userDetails.getUsername() + "profile");
        userInfo.put("picture", userDetails.getUsername() + "picture");
        userInfo.put("website", userDetails.getUsername() + "website");
        userInfo.put("email", "user1@example.com");
        userInfo.put("email_verified", false);
        userInfo.put("gender", userDetails.getUsername() + "gender");
        userInfo.put("birthdate", "2000-01-01");
        userInfo.put("zoneinfo", userDetails.getUsername() + "zoneinfo");
        userInfo.put("locale", "en-US");
        userInfo.put("phone_number", "+1 (425) 555-1212");
        userInfo.put("phone_number_verified", false);
        userInfo.put("address", Map.of("address1", userDetails.getUsername() + "address"));
        userInfo.put("updated_at", Instant.now().getEpochSecond());
        return userInfo;
    }
}
