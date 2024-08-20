package io.jenkins.plugins.security.scan.extension.pipeline;

public interface PrCommentScan {
    public Boolean isBlackducksca_prComment_enabled();

    public Boolean isBlackducksca_prComment_enabled_actualValue();

    @Deprecated
    public Boolean isBlackduck_automation_prcomment();

    @Deprecated
    public Boolean isBlackduck_automation_prcomment_actualValue();

    @Deprecated
    public Boolean isBlackduck_prComment_enabled();

    @Deprecated
    public Boolean isBlackduck_prComment_enabled_actualValue();

    @Deprecated
    public Boolean isCoverity_automation_prcomment();

    @Deprecated
    public Boolean isCoverity_automation_prcomment_actualValue();

    public Boolean isCoverity_prComment_enabled();

    public Boolean isCoverity_prComment_enabled_actualValue();

    public Boolean isPolaris_prComment_enabled();

    public Boolean isPolaris_prComment_enabled_actualValue();
}
