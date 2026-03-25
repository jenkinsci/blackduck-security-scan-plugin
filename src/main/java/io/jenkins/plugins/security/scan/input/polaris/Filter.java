package io.jenkins.plugins.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Filter {
    @JsonProperty("severities")
    private List<String> severities;

    @JsonProperty("by")
    private String by;

    public List<String> getSeverities() {
        return severities;
    }

    public void setSeverities(List<String> severities) {
        this.severities = severities;
    }

    public String getBy() {
        return by;
    }

    public void setBy(String by) {
        this.by = by;
    }
}
