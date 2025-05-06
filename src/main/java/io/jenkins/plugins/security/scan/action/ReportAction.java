package io.jenkins.plugins.security.scan.action;

import hudson.model.Action;
import hudson.model.Run;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import java.util.List;
import jenkins.security.stapler.StaplerDispatchable;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

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

    @StaplerDispatchable
    public SecurityIssue getIssue(int index) {
        if (index >= 0 && index < issues.size()) {
            return issues.get(index);
        }
        return null;
    }

    public Object getDynamic(String token, StaplerRequest req, StaplerResponse rsp) {
        if (token.startsWith("issue")) {
            String indexStr = token.substring(5); // "issue" prefix is 5 characters
            try {
                int index = Integer.parseInt(indexStr);
                if (index >= 0 && index < issues.size()) {
                    return new IssueDetailAction(this, index);
                }
            } catch (NumberFormatException e) {
                // Invalid index
            }
        }
        return null;
    }
}
