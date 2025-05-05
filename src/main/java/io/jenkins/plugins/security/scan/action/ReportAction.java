package io.jenkins.plugins.security.scan.action;

import hudson.model.Action;
import hudson.model.Run;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;

import java.util.List;

public class ReportAction implements Action {
    private final Run<?, ?> run;
    private final List<SecurityIssue> issues;

    public ReportAction(Run<?, ?> run, List<SecurityIssue> issues) {
        this.run = run;
        this.issues = issues;
    }

    @Override
    public String getIconFileName() {
        return ApplicationConstants.BLACK_DUCK_LOGO_FILE_NAME;
    }

    @Override
    public String getDisplayName() {
        return "Black Duck Security Report";
    }

    @Override
    public String getUrlName() {
        return "security-report";
    }

    public Run<?, ?> getRun() {
        return run;
    }

    public List<SecurityIssue> getIssues() {
        return issues;
    }

    public int getIssueCount() {
        return issues.size();
    }
}
