package org.azidp4j.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Value with language tags.
 *
 * <p>Like following example. <ui>
 * <li>name=inaba
 * <li>name#ja=いなば
 * <li>name#en=inaba </ui>
 *
 * @param <T>
 */
public class HumanReadable<T> {
    private final String key;
    private final T defaultValue;
    private final Map<String, T> tags;

    /**
     * Constructor.
     *
     * <p>For following example, <ui>
     * <li>name=inabadef
     * <li>name#ja=いなばja
     * <li>name#en=inabaen </ui> construct instance like <code>
     *     new HumanReadable("name", "inaba", Map.of("ja", "いなばja", "en", "inabaen")</code>
     */
    public HumanReadable(String key, T defaultValue, Map<String, T> tags) {
        this.key = key;
        this.defaultValue = defaultValue;
        if (tags != null) {
            this.tags = tags;
        } else {
            this.tags = Collections.emptyMap();
        }
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

        return tags.get(tag);
    }

    public Map<String, T> toMap() {
        var merge = new HashMap<String, T>();
        tags.forEach((tag, value) -> merge.put(key + "#" + tag, value));
        merge.put(key, defaultValue);
        return merge;
    }
}
