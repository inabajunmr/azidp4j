package org.azidp4j.springsecuritysample.user;

import java.time.Instant;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/** Listner for saving user authentication time */
@Service
public class UserAuthenticationSuccessListener
        implements ApplicationListener<AuthenticationSuccessEvent> {

    private final UserStore userStore;

    public UserAuthenticationSuccessListener(UserStore userStore) {
        this.userStore = userStore;
    }

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        String userName = ((UserDetails) event.getAuthentication().getPrincipal()).getUsername();
        var user = userStore.find(userName);
        user.put("auth_time_sec", Instant.now().getEpochSecond());
    }
}
