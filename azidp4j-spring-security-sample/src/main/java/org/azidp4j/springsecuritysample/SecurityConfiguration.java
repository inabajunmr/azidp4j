package org.azidp4j.springsecuritysample;

import static org.springframework.security.config.Customizer.withDefaults;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import org.azidp4j.springsecuritysample.user.UserInfo;
import org.azidp4j.springsecuritysample.user.UserStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Value("${endpoint}")
    private String endpoint;

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
                                                "/.well-known/openid-configuration")
                                        .permitAll()
                                        //
                                        // .mvcMatchers("/client")
                                        //
                                        // .hasAnyAuthority("SCOPE_client", "SCOPE_default")
                                        .anyRequest()
                                        .authenticated())
                .httpBasic(withDefaults())
                .formLogin(withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
        http.httpBasic().disable();
        http.csrf().ignoringAntMatchers("/authorize", "/token", "/client");
        // @formatter:on
        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        var userStore = userStore();
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

    @Bean
    public UserStore userStore() {
        return new UserStore();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        DefaultJOSEObjectTypeVerifier<SecurityContext> verifier =
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"));
        NimbusJwtDecoder decoder =
                NimbusJwtDecoder.withJwkSetUri(endpoint + "/.well-known/jwks.json")
                        .jwsAlgorithm(SignatureAlgorithm.ES256)
                        .jwtProcessorCustomizer(
                                (processor) -> processor.setJWSTypeVerifier(verifier))
                        .build();
        return decoder;
    }
}
