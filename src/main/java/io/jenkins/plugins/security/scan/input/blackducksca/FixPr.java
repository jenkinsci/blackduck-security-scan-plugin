package io.jenkins.plugins.security.scan.input.blackducksca;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class FixPr {
    @JsonProperty("enabled")
    private Boolean enabled;

    @JsonProperty("maxCount")
    private Integer maxCount;

    @JsonProperty("useUpgradeGuidance")
    private List<String> useUpgradeGuidance;

    @JsonProperty("filter")
    private Filter filter;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Integer getMaxCount() {
        return maxCount;
    }

    public void setMaxCount(Integer maxCount) {
        this.maxCount = maxCount;
    }

    public List<String> getUseUpgradeGuidance() {
        return useUpgradeGuidance;
    }

    public void setUseUpgradeGuidance(List<String> useUpgradeGuidance) {
        this.useUpgradeGuidance = useUpgradeGuidance;
    }

    public Filter getFilter() {
        return filter;
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
    }
}
