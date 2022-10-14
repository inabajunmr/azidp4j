package org.azidp4j.springsecuritysample;

import org.azidp4j.client.ClientStore;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.azidp4j.token.accesstoken.AccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenService;
import org.azidp4j.token.accesstoken.inmemory.InMemoryAccessTokenStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StoreConfiguration {

    @Bean
    public AccessTokenService accessTokenService() {
        return new InMemoryAccessTokenService(new InMemoryAccessTokenStore());
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
