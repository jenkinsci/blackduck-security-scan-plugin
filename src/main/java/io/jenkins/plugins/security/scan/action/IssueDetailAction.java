package io.jenkins.plugins.security.scan.action;

import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

public class IssueDetailAction {
    private final ReportAction parent;
    private final int issueIndex;

    public IssueDetailAction(ReportAction parent, int issueIndex) {
        this.parent = parent;
        this.issueIndex = issueIndex;
    }

    public SecurityIssue getIssue() {
        return parent.getIssue(issueIndex);
    }

    public ReportAction getParent() {
        return parent;
    }

    public String getDisplayName() {
        SecurityIssue issue = getIssue();
        if (issue != null) {
            return "Issue Detail: " + issue.getRuleId();
        }
        return "Issue Detail";
    }

    public String getRenderedMessage() {
        if (getIssue() != null && getIssue().getHelpMarkdown() != null) {
            Parser parser = Parser.builder().build();
            Node document = parser.parse(getIssue().getMessage());
            HtmlRenderer renderer = HtmlRenderer.builder().build();
            return renderer.render(document);
        }
        return "";
    }

    public String getRenderedHelpMarkdown() {
        if (getIssue() != null && getIssue().getHelpMarkdown() != null) {
            Parser parser = Parser.builder().build();
            Node document = parser.parse(getIssue().getHelpMarkdown());
            HtmlRenderer renderer = HtmlRenderer.builder().build();
            return renderer.render(document);
        }
        return "";
    }
}
