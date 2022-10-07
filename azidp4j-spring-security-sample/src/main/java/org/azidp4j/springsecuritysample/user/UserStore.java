package org.azidp4j.springsecuritysample.user;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class UserStore {

    private final Map<String, UserInfo> STORE = new ConcurrentHashMap<>();

    public void save(UserInfo user) {
        STORE.put((String) user.get("sub"), user);
    }

    public UserInfo find(String sub) {
        return STORE.get(sub);
    }
}
