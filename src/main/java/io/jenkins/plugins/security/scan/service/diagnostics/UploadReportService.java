package io.jenkins.plugins.security.scan.service.diagnostics;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.enums.ReportType;

public class UploadReportService {
    private final Run<?, ?> run;
    private final TaskListener listener;
    private final LoggerWrapper logger;
    private final Launcher launcher;
    private final EnvVars envVars;
    private final ArtifactArchiver artifactArchiver;

    public UploadReportService(
            Run<?, ?> run,
            TaskListener listener,
            Launcher launcher,
            EnvVars envVars,
            ArtifactArchiver artifactArchiver) {
        this.run = run;
        this.listener = listener;
        this.logger = new LoggerWrapper(listener);
        this.launcher = launcher;
        this.envVars = envVars;
        this.artifactArchiver = artifactArchiver;
    }

    public void archiveReports(FilePath reportsPath, ReportType reportType) {
        try {
            FilePath path = reportType == ReportType.SARIF ? reportsPath.getParent() : reportsPath;
            if (path != null) {
                if (path.exists()) {
                    logger.info(
                            "Archiving " + reportType.name() + " jenkins artifact from: " + reportsPath.getRemote());
                    artifactArchiver.perform(run, path, envVars, launcher, listener);
                } else {
                    logger.error(
                            ApplicationConstants.ARCHIVING_REPORTS_FAILED_AS_REPORT_PATH_NOT_FOUND,
                            reportType.name(),
                            reportType.name(),
                            path.getRemote());
                    return;
                }
            }
        } catch (Exception e) {
            logger.error(ApplicationConstants.ARCHIVING_REPORTS_IN_JENKINS_ARTIFACT, reportType.name(), e.getMessage());
            Thread.currentThread().interrupt();
            return;
        }

        logger.info(reportType.name() + " archived successfully in jenkins artifact");
    }
}
