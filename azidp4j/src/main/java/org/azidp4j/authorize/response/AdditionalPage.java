package org.azidp4j.authorize.response;

import java.util.List;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;

public class AdditionalPage {
    public final Prompt prompt;
    public final Display display;
    public final String clientId;
    public final String scope;
    public final List<String> acrValues;
    public List<String> uiLocales;
    public String expectedUserSubject;
    public String loginHint;

    public AdditionalPage(
            Prompt prompt,
            Display display,
            String clientId,
            String scope,
            List<String> acrValues,
            List<String> uiLocales,
            String expectedUserSubject,
            String loginHint) {
        this.prompt = prompt;
        this.display = display;
        this.clientId = clientId;
        this.scope = scope;
        this.acrValues = acrValues;
        this.uiLocales = uiLocales;
        this.expectedUserSubject = expectedUserSubject;
        this.loginHint = loginHint;
    }
}
