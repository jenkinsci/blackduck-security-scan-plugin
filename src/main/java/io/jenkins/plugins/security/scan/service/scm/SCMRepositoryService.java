package io.jenkins.plugins.security.scan.service.scm;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import hudson.EnvVars;
import hudson.model.TaskListener;
import io.jenkins.plugins.gitlabbranchsource.GitLabSCMSource;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.enums.InvokedFrom;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.github.Github;
import io.jenkins.plugins.security.scan.input.scm.gitlab.Gitlab;
import io.jenkins.plugins.security.scan.service.scm.bitbucket.BitbucketRepositoryService;
import io.jenkins.plugins.security.scan.service.scm.github.GithubRepositoryService;
import io.jenkins.plugins.security.scan.service.scm.gitlab.GitlabRepositoryService;
import java.util.Map;
import jenkins.model.Jenkins;
import jenkins.scm.api.SCMSource;
import jenkins.scm.api.SCMSourceOwner;
import org.jenkinsci.plugins.github_branch_source.GitHubSCMSource;

public class SCMRepositoryService {
    private final TaskListener listener;
    private final EnvVars envVars;
    private final LoggerWrapper logger;

    // Regex pattern to match Bitbucket Cloud URLs with optional user authentication
    private static final String BITBUCKET_CLOUD_URL_PATTERN = "https://.*@?bitbucket\\.org.*";

    public SCMRepositoryService(TaskListener listener, EnvVars envVars) {
        this.listener = listener;
        this.envVars = envVars;
        this.logger = new LoggerWrapper(listener);
    }

    public Object fetchSCMRepositoryDetails(
            Map<String, Boolean> installedBranchSourceDependencies, Map<String, Object> scanParameters)
            throws PluginExceptionHandler {
        String pullRequestNumber = envVars.get(ApplicationConstants.ENV_CHANGE_ID_KEY);
        Integer projectRepositoryPullNumber = pullRequestNumber != null ? Integer.parseInt(pullRequestNumber) : null;
        String branchName = envVars.get(ApplicationConstants.BRANCH_NAME);
        Object scmObject = null;

        SCMSource scmSource = findSCMSource();
        if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof BitbucketSCMSource) {
            BitbucketRepositoryService bitbucketRepositoryService = new BitbucketRepositoryService(listener);
            BitbucketSCMSource bitbucketSCMSource = (BitbucketSCMSource) scmSource;
            scmObject = bitbucketRepositoryService.fetchBitbucketRepositoryDetails(
                    scanParameters, bitbucketSCMSource, projectRepositoryPullNumber, branchName);
        } else if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitHubSCMSource) {
            GithubRepositoryService githubRepositoryService = new GithubRepositoryService(listener);
            GitHubSCMSource gitHubSCMSource = (GitHubSCMSource) scmSource;

            String repositoryOwner = gitHubSCMSource.getRepoOwner();
            String repositoryName = gitHubSCMSource.getRepository();
            String apiUri = gitHubSCMSource.getApiUri();

            scmObject = githubRepositoryService.createGithubObject(
                    scanParameters, repositoryName, repositoryOwner, projectRepositoryPullNumber, branchName, apiUri);
        } else if (installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitLabSCMSource) {
            GitlabRepositoryService gitlabRepositoryService = new GitlabRepositoryService(listener);
            GitLabSCMSource gitLabSCMSource = (GitLabSCMSource) scmSource;

            String repositoryUrl = gitLabSCMSource.getHttpRemote();
            String repositoryName = gitLabSCMSource.getProjectPath();

            scmObject = gitlabRepositoryService.createGitlabObject(
                    scanParameters, repositoryName, projectRepositoryPullNumber, branchName, repositoryUrl);
        }

        setRepositoryName(scmObject);

        return scmObject;
    }

    public SCMSource findSCMSource() {
        String jobName = envVars.get(ApplicationConstants.ENV_JOB_NAME_KEY);
        jobName = jobName.contains("/") ? jobName.substring(0, jobName.lastIndexOf('/')) : jobName;

        Jenkins jenkins = Jenkins.getInstanceOrNull();
        SCMSourceOwner owner = jenkins != null ? jenkins.getItemByFullName(jobName, SCMSourceOwner.class) : null;
        if (owner != null) {
            for (SCMSource scmSource : owner.getSCMSources()) {
                if (owner.getSCMSource(scmSource.getId()) != null) {
                    return scmSource;
                }
            }
        }
        return null;
    }

    public void setRepositoryName(Object scmObject) {
        String repositoryName = null;
        if (scmObject instanceof Bitbucket) {
            Bitbucket bitbucket = (Bitbucket) scmObject;
            repositoryName = bitbucket.getProject().getRepository().getName();
        } else if (scmObject instanceof Github) {
            Github github = (Github) scmObject;
            repositoryName = github.getRepository().getName();
        } else if (scmObject instanceof Gitlab) {
            Gitlab gitlab = (Gitlab) scmObject;
            String fullName = gitlab.getRepository().getName();
            repositoryName = extractLastPart(fullName);
        }

        RepositoryDetailsHolder.setRepositoryName(repositoryName);
    }

    private static String extractLastPart(String fullRepoName) {
        if (fullRepoName != null && !fullRepoName.isEmpty()) {
            int lastSlashIndex = fullRepoName.lastIndexOf('/');
            if (lastSlashIndex != -1 && lastSlashIndex < fullRepoName.length() - 1) {
                return fullRepoName.substring(lastSlashIndex + 1);
            }
        }

        return fullRepoName;
    }

    public InvokedFrom getInvokedFrom(
            Map<String, Boolean> installedBranchSourceDependencies, String jobType, SCMSource scmSource) {
        InvokedFrom invokedFrom;

        if (jobType.equalsIgnoreCase(ApplicationConstants.MULTIBRANCH_JOB_TYPE_NAME)) {
            invokedFrom = getInvokedFromForMultiBranchJob(installedBranchSourceDependencies, scmSource);
        } else if (jobType.equalsIgnoreCase(ApplicationConstants.FREESTYLE_JOB_TYPE_NAME)) {
            invokedFrom = InvokedFrom.INT_JENKINS_FREESTYLE;
        } else {
            invokedFrom = InvokedFrom.INT_JENKINS_PIPELINE;
        }

        return invokedFrom;
    }

    private InvokedFrom getInvokedFromForMultiBranchJob(
            Map<String, Boolean> installedBranchSourceDependencies, SCMSource scmSource) {
        String gitURL = envVars.get(ApplicationConstants.GIT_URL);

        if (isBitbucketSource(installedBranchSourceDependencies, scmSource)) {
            return determineBitbucketType(gitURL);
        }

        if (isGithubSource(installedBranchSourceDependencies, scmSource)) {
            return determineGithubType(gitURL);
        }

        if (isGitlabSource(installedBranchSourceDependencies, scmSource)) {
            return determineGitlabType(gitURL);
        }

        return null;
    }

    private boolean isBitbucketSource(Map<String, Boolean> installedBranchSourceDependencies, SCMSource scmSource) {
        return installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.BITBUCKET_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof BitbucketSCMSource;
    }

    private InvokedFrom determineBitbucketType(String gitURL) {
        if (gitURL != null && gitURL.matches(BITBUCKET_CLOUD_URL_PATTERN)) {
            return InvokedFrom.INT_BITBUCKET_CLOUD;
        }
        return InvokedFrom.INT_BITBUCKET_EE;
    }

    private boolean isGithubSource(Map<String, Boolean> installedBranchSourceDependencies, SCMSource scmSource) {
        return installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITHUB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitHubSCMSource;
    }

    private InvokedFrom determineGithubType(String gitURL) {
        if (gitURL != null && gitURL.startsWith(GithubRepositoryService.GITHUB_CLOUD_HOST_URL)) {
            return InvokedFrom.INT_GITHUB_CLOUD;
        }
        return InvokedFrom.INT_GITHUB_EE;
    }

    private boolean isGitlabSource(Map<String, Boolean> installedBranchSourceDependencies, SCMSource scmSource) {
        return installedBranchSourceDependencies.getOrDefault(
                        ApplicationConstants.GITLAB_BRANCH_SOURCE_PLUGIN_NAME, false)
                && scmSource instanceof GitLabSCMSource;
    }

    private InvokedFrom determineGitlabType(String gitURL) {
        if (gitURL != null && gitURL.startsWith(GitlabRepositoryService.GITLAB_CLOUD_HOST_URL)) {
            return InvokedFrom.INT_GITLAB_CLOUD;
        }
        return InvokedFrom.INT_GITLAB_EE;
    }
}
