package io.jenkins.plugins.security.scan.extension.pipeline;

public interface FixPrScan {
    public Boolean isBlackducksca_fixpr_enabled();

    public Boolean isBlackducksca_fixpr_enabled_actualValue();

    public String getBlackducksca_fixpr_filter_severities();

    public String getBlackducksca_fixpr_useUpgradeGuidance();

    public Integer getBlackducksca_fixpr_maxCount();
}
