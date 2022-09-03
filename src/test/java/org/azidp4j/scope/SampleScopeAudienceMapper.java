package org.azidp4j.scope;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class SampleScopeAudienceMapper implements ScopeAudienceMapper {
    @Override
    public Set<String> map(String scope) {
        return Arrays.stream(scope.split(" "))
                .map(s -> "http://" + s.split(":")[0] + ".example.com")
                .collect(Collectors.toSet());
    }
}
