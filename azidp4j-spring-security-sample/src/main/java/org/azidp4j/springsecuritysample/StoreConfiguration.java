package org.azidp4j.springsecuritysample;

import com.nimbusds.jose.jwk.JWKSet;
import org.azidp4j.AzIdPConfig;
import org.azidp4j.client.ClientStore;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.jwt.JWSIssuer;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.jwt.JwtAccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StoreConfiguration {

    @Autowired JWKSet jwkSet;

    @Autowired AzIdPConfig config;

    @Bean
    public AccessTokenService accessTokenService(AzIdPConfig config) {
        //        return new InMemoryAccessTokenService(new InMemoryAccessTokenStore());

        return new JwtAccessTokenService(jwkSet, new JWSIssuer(jwkSet), config.issuer, () -> "123");
    }

    @Bean
    public ClientStore clientStore() {
        return new InMemoryClientStore();
    }

    @Bean
    public InMemoryUserConsentStore InMemoryUserConsentStore() {
        return new InMemoryUserConsentStore();
    }
}
