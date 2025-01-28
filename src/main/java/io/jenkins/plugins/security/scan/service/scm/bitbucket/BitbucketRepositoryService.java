package io.jenkins.plugins.security.scan.service.scm.bitbucket;

import com.cloudbees.jenkins.plugins.bitbucket.BitbucketSCMSource;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketApi;
import com.cloudbees.jenkins.plugins.bitbucket.api.BitbucketRepository;
import hudson.model.TaskListener;
import io.jenkins.plugins.security.scan.exception.PluginExceptionHandler;
import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.ErrorCode;
import io.jenkins.plugins.security.scan.global.LoggerWrapper;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Bitbucket;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Repository;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.User;
import io.jenkins.plugins.security.scan.input.scm.bitbucket.Workspace;
import io.jenkins.plugins.security.scan.input.scm.common.Branch;
import io.jenkins.plugins.security.scan.input.scm.common.Pull;
import io.jenkins.plugins.security.scan.service.ToolsParameterService;
import java.util.Map;

public class BitbucketRepositoryService {
    private final LoggerWrapper logger;
    private static String BITBUCKET_CLOUD_HOST_URL = "https://bitbucket.org";

    public BitbucketRepositoryService(TaskListener listener) {
        this.logger = new LoggerWrapper(listener);
    }

    public Bitbucket fetchBitbucketRepositoryDetails(
            Map<String, Object> scanParameters,
            BitbucketSCMSource bitbucketSCMSource,
            Integer projectRepositoryPullNumber,
            String branchName)
            throws PluginExceptionHandler {

        String bitbucketToken = (String) scanParameters.get(ApplicationConstants.BITBUCKET_TOKEN_KEY);
        String bitbucketUsername = (String) scanParameters.get(ApplicationConstants.BITBUCKET_USERNAME_KEY);
        String serverUrl = bitbucketSCMSource.getServerUrl();
        String repositoryName = null;
        String projectKey = null;
        boolean isPrCommentSet = ToolsParameterService.isPrCommentValueSet(scanParameters);
        boolean isFixPrValueSet = ToolsParameterService.isFixPrValueSet(scanParameters);

        if (isPrCommentSet && Utility.isStringNullOrBlank(bitbucketToken)) {
            logger.error(ApplicationConstants.PRCOMMENT_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND, "Bitbucket");
            throw new PluginExceptionHandler(ErrorCode.NO_BITBUCKET_TOKEN_FOUND);
        }

        if (isFixPrValueSet && Utility.isStringNullOrBlank(bitbucketToken)) {
            logger.error(ApplicationConstants.FIXPR_SET_TRUE_BUT_NO_SCM_TOKEN_FOUND, "Bitbucket");
            throw new PluginExceptionHandler(ErrorCode.NO_BITBUCKET_TOKEN_FOUND);
        }

        BitbucketApi bitbucketApiFromSCMSource = bitbucketSCMSource.buildBitbucketClient(
                bitbucketSCMSource.getRepoOwner(), bitbucketSCMSource.getRepository());

        BitbucketRepository bitbucketRepository = null;
        try {
            bitbucketRepository = bitbucketApiFromSCMSource.getRepository();
        } catch (Exception e) {
            logger.error(
                    ApplicationConstants.EXCEPTION_WHILE_GETTING_THE_BITBUCKET_REPOSITORY_FROM_BITBUCKET_API,
                    e.getMessage());
            Thread.currentThread().interrupt();
        }

        if (bitbucketRepository != null) {
            repositoryName = bitbucketRepository.getRepositoryName();
            projectKey = bitbucketRepository.getOwnerName();
        }

        boolean isBitbucketCloud = serverUrl != null && serverUrl.startsWith(BITBUCKET_CLOUD_HOST_URL);

        if (projectRepositoryPullNumber != null) {
            logger.info("BitBucket bitbucketUsername: " + bitbucketUsername);
            logger.info("BitBucket repositoryName: " + repositoryName);
            logger.info("BitBucket " + (isBitbucketCloud ? "workspaceId: " : "projectKey: ") + projectKey);
            logger.info("BitBucket projectRepositoryPullNumber: " + projectRepositoryPullNumber);
            logger.info("BitBucket branchName: " + branchName);
            logger.info("BitBucket serverUrl: " + serverUrl);
        }

        return createBitbucketObject(
                serverUrl,
                bitbucketToken,
                projectRepositoryPullNumber,
                repositoryName,
                branchName,
                projectKey,
                bitbucketUsername);
    }

    public static Bitbucket createBitbucketObject(
            String serverUrl,
            String bitbucketToken,
            Integer projectRepositoryPullNumber,
            String repositoryName,
            String branchName,
            String projectKey,
            String bitbucketUsername) {
        boolean isBitbucketCloud = serverUrl != null && serverUrl.startsWith(BITBUCKET_CLOUD_HOST_URL);
        Bitbucket bitbucket = new Bitbucket();
        bitbucket.getApi().setUrl(isBitbucketCloud ? "" : serverUrl);
        bitbucket.getApi().setToken(bitbucketToken);
        Repository repository = new Repository();
        repository.setBranch(new Branch());
        repository.setName(repositoryName);

        if (projectRepositoryPullNumber != null) {
            Pull pull = new Pull();
            pull.setNumber(projectRepositoryPullNumber);
            repository.setPull(pull);
        }

        repository.getBranch().setName(branchName);

        if (!Utility.isStringNullOrBlank(bitbucketUsername) && isBitbucketCloud) {
            User user = new User();
            user.setName(bitbucketUsername);
            bitbucket.getApi().setUser(user);
        }

        if (isBitbucketCloud) {
            Workspace workspace = new Workspace();
            workspace.setId(projectKey);
            bitbucket.setWorkspace(workspace);
        } else {
            bitbucket.getProject().setKey(projectKey);
        }

        bitbucket.getProject().setRepository(repository);

        return bitbucket;
    }
}
