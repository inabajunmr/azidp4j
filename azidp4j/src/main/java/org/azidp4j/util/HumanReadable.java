package org.azidp4j.util;

import java.util.HashMap;
import java.util.Map;

public class HumanReadable<T> {
    private final String key;
    private final T defaultValue;
    private final Map<String, T> tags;

    public HumanReadable(String key, T defaultValue, Map<String, T> tags) {
        this.key = key;
        this.defaultValue = defaultValue;
        this.tags = tags;
    }

    public HumanReadable put(String tag, T value) {
        if (tag != null) {
            var merge = new HashMap<String, T>();
            if (tags != null) {
                merge.putAll(tags);
            }
            merge.put(tag, value);
            return new HumanReadable<>(this.key, this.defaultValue, Map.copyOf(merge));
        }
        return new HumanReadable<>(this.key, value, this.tags);
    }

    public String getKey() {
        return key;
    }

    public T getDefault() {
        return defaultValue;
    }

    public T get(String tag) {
        if (tag == null) {
            return defaultValue;
        }
        if (tags == null) {
            return null;
        }

        return tags.get(tag);
    }

    public Map<String, T> toMap() {
        var merge = new HashMap<String, T>();
        tags.entrySet().forEach((kv) -> merge.put(key + "#" + kv.getKey(), kv.getValue()));
        merge.put(key, defaultValue);
        return merge;
    }
}
