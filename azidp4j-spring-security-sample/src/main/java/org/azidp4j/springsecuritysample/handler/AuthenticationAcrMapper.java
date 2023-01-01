package org.azidp4j.springsecuritysample.handler;

import org.azidp4j.springsecuritysample.authentication.AcrValue;
import org.azidp4j.springsecuritysample.authentication.SelfReportedAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

public class AuthenticationAcrMapper {

    public static AcrValue map(Authentication authentication) {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return AcrValue.pwd;
        } else if (authentication instanceof SelfReportedAuthenticationToken) {
            return AcrValue.self_reported;
        }
        throw new AssertionError(authentication.getClass().getName() + " is not supported");
    }
}
