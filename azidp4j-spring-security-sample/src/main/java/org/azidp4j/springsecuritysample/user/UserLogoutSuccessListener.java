package org.azidp4j.springsecuritysample.user;

import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

/** Listner for removing user authentication time */
@Service
public class UserLogoutSuccessListener implements ApplicationListener<LogoutSuccessEvent> {

    private final UserStore userStore;

    public UserLogoutSuccessListener(UserStore userStore) {
        this.userStore = userStore;
    }

    @Override
    public void onApplicationEvent(LogoutSuccessEvent event) {
        String userName = ((UserDetails) event.getAuthentication().getPrincipal()).getUsername();
        var user = userStore.find(userName);
        user.remove("auth_time_sec");
    }
}
