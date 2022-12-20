package org.azidp4j.authorize.response;

import java.util.List;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;

public class AdditionalPage {
    public final Prompt prompt;
    public final Display display;
    public final String clientId;
    public final String scope;
    public List<String> uiLocales;
    public String expectedUserSubject;

    public AdditionalPage(
            Prompt prompt,
            Display display,
            String clientId,
            String scope,
            List<String> uiLocales,
            String expectedUserSubject) {
        this.prompt = prompt;
        this.display = display;
        this.clientId = clientId;
        this.scope = scope;
        this.uiLocales = uiLocales;
        this.expectedUserSubject = expectedUserSubject;
    }
}
