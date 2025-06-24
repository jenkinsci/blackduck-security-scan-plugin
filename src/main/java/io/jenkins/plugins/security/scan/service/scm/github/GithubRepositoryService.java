package io.jenkins.plugins.security.scan.service.scm.github;

import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.scm.common.Pull;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.github.Host;
import io.jenkins.plugins.security.scan.service.ToolsParameterService;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

public class GithubRepositoryService {
    private final LoggerWrapper logger;
    public static final String GITHUB_CLOUD_HOST_URL = "https://github.com/";
    public static final String GITHUB_CLOUD_API_URI = "https://api.github.com";
    private String INVALID_GITHUB_REPO_URL = "Invalid Github repository URL";

    public GithubRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Github createGithubObject(
            Map<String, Object> scanParameters,
            String repositoryName,
            String repositoryOwner,
            Integer projectRepositoryPullNumber,
            String branchName,
            String githubApiUri)
            throws PluginExceptionHandler {
        String githubToken = (String) scanParameters.get(ApplicationConstants.GITHUB_TOKEN_KEY);
        boolean isPrCommentSet = ToolsParameterService.isPrCommentValueSet(scanParameters);
        boolean isFixPrValueSet = ToolsParameterService.isFixPrValueSet(scanParameters);

        if (isPrCommentSet && Utility.isStringNullOrBlank(githubToken)) {
            logger.error(ApplicationConstants.PRCOMMENT_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND, "GitHub");
            throw new PluginExceptionHandler(ErrorCode.NO_GITHUB_TOKEN_FOUND);
        }

        if (isFixPrValueSet && Utility.isStringNullOrBlank(githubToken)) {
            logger.error(ApplicationConstants.FIXPR_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND, "GitHub");
            throw new PluginExceptionHandler(ErrorCode.NO_GITHUB_TOKEN_FOUND);
        }

        Github github = new Github();

        github.getUser().setToken(githubToken);
        github.getRepository().setName(repositoryName);
        github.getRepository().getOwner().setName(repositoryOwner);

        Pull pull = new Pull();
        pull.setNumber(projectRepositoryPullNumber);
        github.getRepository().setPull(pull);

        github.getRepository().getBranch().setName(branchName);

        String githubHostUrl = extractGitHubHost(githubApiUri);

        if (projectRepositoryPullNumber != null || isFixPrValueSet) {
            logger.info("Github repositoryName: " + repositoryName);
            logger.info("Github repositoryOwner: " + repositoryOwner);
            if (projectRepositoryPullNumber != null) {
                logger.info("Github projectRepositoryPullNumber: " + projectRepositoryPullNumber);
            }
            logger.info("Github branchName: " + branchName);
            logger.info("Github githubHostUrl: " + githubHostUrl);
        }

        if (githubHostUrl.equals(INVALID_GITHUB_REPO_URL)) {
            logger.error(INVALID_GITHUB_REPO_URL);
            throw new PluginExceptionHandler(ErrorCode.INVALID_GITHUB_URL);
        } else {
            if (!githubHostUrl.startsWith(GITHUB_CLOUD_HOST_URL)) {
                github.setHost(new Host());
                github.getHost().setUrl(githubHostUrl);
            }
        }

        return github;
    }

    public String extractGitHubHost(String githubApiUri) {
        try {
            return GITHUB_CLOUD_API_URI.equals(githubApiUri)
                    ? GITHUB_CLOUD_HOST_URL
                    : String.format("%s", StringUtils.removeEnd(githubApiUri, "api/v3"));
        } catch (Exception e) {
            return INVALID_GITHUB_REPO_URL;
        }
    }
}
