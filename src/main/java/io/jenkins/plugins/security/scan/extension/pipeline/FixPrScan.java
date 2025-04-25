package io.jenkins.plugins.security.scan.extension.pipeline;

public interface FixPrScan {
    Boolean isBlackducksca_fixpr_enabled();

    Boolean isBlackducksca_fixpr_enabled_actualValue();

    String getBlackducksca_fixpr_filter_severities();

    String getBlackducksca_fixpr_useUpgradeGuidance();

    Integer getBlackducksca_fixpr_maxCount();
}
