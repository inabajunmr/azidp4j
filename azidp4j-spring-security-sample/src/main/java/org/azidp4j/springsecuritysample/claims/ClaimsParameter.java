package org.azidp4j.springsecuritysample.claims;

import java.util.List;

public class ClaimsParameter {

    final List<ClaimsValue> values;
    private final boolean isEssential;

    public ClaimsParameter(List<ClaimsValue> values, boolean isEssential) {
        this.values = values;
        this.isEssential = isEssential;
    }

    public List<ClaimsValue> getValues() {
        return values;
    }

    public boolean contains(ClaimsValue value) {
        return this.values.contains(value);
    }

    public boolean isEssential() {
        return isEssential;
    }
}
