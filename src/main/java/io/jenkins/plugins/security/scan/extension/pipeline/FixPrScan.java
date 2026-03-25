package io.jenkins.plugins.security.scan.extension.pipeline;

public interface FixPrScan {
    public Boolean isBlackducksca_fixpr_enabled();

    public Boolean isBlackducksca_fixpr_enabled_actualValue();

    public String getBlackducksca_fixpr_filter_severities();

    public String getBlackducksca_fixpr_useUpgradeGuidance();

    public Integer getBlackducksca_fixpr_maxCount();

    public Boolean isPolaris_fixpr_enabled();

    public Boolean isPolaris_fixpr_enabled_actualValue();

    public Integer getPolaris_fixpr_maxCount();

    public Boolean isPolaris_fixpr_createSinglePR();

    public Boolean isPolaris_fixpr_createSinglePR_actualValue();

    public String getPolaris_fixpr_useUpgradeGuidance();

    public String getPolaris_fixpr_filter_severities();

    public String getPolaris_fixpr_filter_by();
}
