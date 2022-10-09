package org.azidp4j.authorize.response;

import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;

public class AdditionalPage {
    public final Prompt prompt;
    public final Display display;

    public AdditionalPage(Prompt prompt, Display display) {
        this.prompt = prompt;
        this.display = display;
    }
}
