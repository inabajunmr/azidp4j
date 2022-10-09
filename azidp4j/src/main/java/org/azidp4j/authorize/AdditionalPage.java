package org.azidp4j.authorize;

public class AdditionalPage {
    public final Prompt prompt;
    public final Display display;

    public AdditionalPage(Prompt prompt, Display display) {
        this.prompt = prompt;
        this.display = display;
    }
}
