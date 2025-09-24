package io.jenkins.plugins.security.scan.extension.pipeline;

public interface PrCommentScan {
    public Boolean isBlackducksca_prComment_enabled();

    public Boolean isBlackducksca_prComment_enabled_actualValue();

    @Deprecated
    public Boolean isBlackduck_prComment_enabled();

    @Deprecated
    public Boolean isBlackduck_prComment_enabled_actualValue();

    public Boolean isCoverity_prComment_enabled();

    public Boolean isCoverity_prComment_enabled_actualValue();

	public String getCoverity_prComment_impacts();

    public Boolean isPolaris_prComment_enabled();

    public Boolean isPolaris_prComment_enabled_actualValue();

    public String getPolaris_prComment_severities();
}
