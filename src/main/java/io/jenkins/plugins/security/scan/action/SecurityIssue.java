package io.jenkins.plugins.security.scan.action;

import java.io.Serializable;

public class SecurityIssue implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String ruleId;
    private final String message;
    private final String filePath;
    private final int line;
    private final String severity;
    private final String toolName;

    public SecurityIssue(String ruleId, String message, String filePath, int line, String severity, String toolName) {
        this.ruleId = ruleId;
        this.message = message;
        this.filePath = filePath;
        this.line = line;
        this.severity = severity;
        this.toolName = toolName;
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
}