package org.azidp4j.authorize.response;

import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;

public class AdditionalPage {
    public final Prompt prompt;
    public final Display display;
    public final String clientId;
    public final String scope;

    public AdditionalPage(Prompt prompt, Display display, String clientId, String scope) {
        this.prompt = prompt;
        this.display = display;
        this.clientId = clientId;
        this.scope = scope;
    }
}
