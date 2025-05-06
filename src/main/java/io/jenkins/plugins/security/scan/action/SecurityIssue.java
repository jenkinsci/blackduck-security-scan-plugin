package io.jenkins.plugins.security.scan.action;

import java.io.Serializable;
import java.util.List;

public class SecurityIssue implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String ruleId;
    private final String message;
    private final String filePath;
    private final int line;
    private final String severity;
    private final String toolName;
    private final String helpMarkdown;
    private final String shortDescription;

    private final List<String> codeSnippet;
    private final int startLineNumber;
    private final int highlightedLineIndex;

    public SecurityIssue(
            String ruleId,
            String message,
            String filePath,
            int line,
            String severity,
            String toolName,
            String helpMarkdown,
            String shortDescription,
            List<String> codeSnippet,
            int startLineNumber,
            int highlightedLineIndex) {
        this.ruleId = ruleId;
        this.message = message;
        this.filePath = filePath;
        this.line = line;
        this.severity = severity;
        this.toolName = toolName;
        this.helpMarkdown = helpMarkdown;
        this.shortDescription = shortDescription;
        this.codeSnippet = codeSnippet;
        this.startLineNumber = startLineNumber;
        this.highlightedLineIndex = highlightedLineIndex;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getMessage() {
        return message;
    }

    public String getFilePath() {
        return filePath;
    }

    public int getLine() {
        return line;
    }

    public String getSeverity() {
        return severity;
    }

    public String getToolName() {
        return toolName;
    }

    public String getHelpMarkdown() {
        return helpMarkdown;
    }

    public String getShortDescription() {
        return shortDescription;
    }

    public List<String> getCodeSnippet() {
        return codeSnippet;
    }

    public int getStartLineNumber() {
        return startLineNumber;
    }

    public int getHighlightedLineIndex() {
        return highlightedLineIndex;
    }
}
