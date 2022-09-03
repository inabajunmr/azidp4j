package org.azidp4j.scope;

import java.util.Set;

public interface ScopeAudienceMapper {
    Set<String> map(String scope);
}
