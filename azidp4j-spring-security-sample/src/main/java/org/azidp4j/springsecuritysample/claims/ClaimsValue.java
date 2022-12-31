package org.azidp4j.springsecuritysample.claims;

import java.util.Objects;

public class ClaimsValue {
    private final String text;
    private final Number number;
    private final Boolean bool;

    private ClaimsValue(String text, Number number, Boolean bool) {
        this.text = text;
        this.number = number;
        this.bool = bool;
    }

    public static ClaimsValue of(String value) {
        return new ClaimsValue(value, null, null);
    }

    public static ClaimsValue of(Number value) {
        return new ClaimsValue(null, value, null);
    }

    public static ClaimsValue of(Boolean value) {
        return new ClaimsValue(null, null, value);
    }

    public boolean isText() {
        return text != null;
    }

    public boolean isNumber() {
        return number != null;
    }

    public boolean isBool() {
        return bool != null;
    }

    public String asText() {
        if (text == null) {
            throw new AssertionError("not text value");
        }
        return text;
    }

    public Number asNumber() {
        if (number == null) {
            throw new AssertionError("not number value");
        }
        return number;
    }

    public Boolean asBool() {
        if (bool == null) {
            throw new AssertionError("not bool value");
        }
        return bool;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClaimsValue that = (ClaimsValue) o;
        return Objects.equals(text, that.text)
                && Objects.equals(number, that.number)
                && Objects.equals(bool, that.bool);
    }

    @Override
    public int hashCode() {
        return Objects.hash(text, number, bool);
    }
}
