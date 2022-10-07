package org.azidp4j.springsecuritysample;

import org.azidp4j.client.ClientStore;
import org.azidp4j.client.InMemoryClientStore;
import org.azidp4j.springsecuritysample.consent.InMemoryUserConsentStore;
import org.azidp4j.token.accesstoken.AccessTokenStore;
import org.azidp4j.token.accesstoken.InMemoryAccessTokenStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class StoreConfiguration {

    @Bean
    public AccessTokenStore accessTokenStore() {
        return new InMemoryAccessTokenStore();
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
