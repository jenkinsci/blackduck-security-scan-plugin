package io.jenkins.plugins.security.scan.input.polaris;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Filter {
    @JsonProperty("severities")
    private List<String> severities;

    @JsonProperty("issueTypes")
    private List<String> issueTypes;

    @JsonProperty("confidence")
    private List<String> confidence;

    public List<String> getSeverities() {
        return severities;
    }

    public void setSeverities(List<String> severities) {
        this.severities = severities;
    }

    public List<String> getIssueTypes() {
        return issueTypes;
    }

    public void setIssueTypes(List<String> issueTypes) {
        this.issueTypes = issueTypes;
    }

    public List<String> getConfidence() {
        return confidence;
    }

    public void setConfidence(List<String> confidence) {
        this.confidence = confidence;
    }
}
