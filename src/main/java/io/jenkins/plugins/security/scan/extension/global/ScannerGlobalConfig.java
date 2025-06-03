package io.jenkins.plugins.security.scan.extension.global;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.security.scan.global.LogMessages;
import io.jenkins.plugins.security.scan.global.ScanCredentialsHelper;
import io.jenkins.plugins.security.scan.global.Utility;
import java.io.Serial;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.util.Collections;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.impl.EnglishReasonPhraseCatalog;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

@Extension
public class ScannerGlobalConfig extends GlobalConfiguration implements Serializable {
    @Serial
    private static final long serialVersionUID = -3129542889827231427L;

    private static final int CONNECTION_TIMEOUT_IN_SECONDS = 120;
    private String AUTHORIZATION_FAILURE = "Could not perform the authorization request: ";
    private String CONNECTION_SUCCESSFUL = "Connection successful.";

    private String blackDuckSCAUrl;
    private String blackDuckSCACredentialsId;
    private String detectInstallationPath;
    private String coverityConnectUrl;
    private String coverityCredentialsId;
    private String coverityInstallationPath;
    private String bridgeDownloadUrlForMac;
    private String bridgeDownloadUrlForWindows;
    private String bridgeDownloadUrlForLinux;
    private String bridgeDownloadVersion;
    private String bridgeInstallationPath;
    private Boolean networkAirGap;
    private String polarisServerUrl;
    private String polarisCredentialsId;
    private String srmUrl;
    private String srmCredentialsId;
    private String srmSCAInstallationPath;
    private String srmSASTInstallationPath;
    private String bitbucketCredentialsId;
    private String githubCredentialsId;
    private String gitlabCredentialsId;

    @DataBoundConstructor
    public ScannerGlobalConfig() {
        load();
    }

    @DataBoundSetter
    public void setBlackDuckSCAUrl(String blackDuckSCAUrl) {
        this.blackDuckSCAUrl = blackDuckSCAUrl;
        save();
    }

    @DataBoundSetter
    public void setBlackDuckSCACredentialsId(String blackDuckSCACredentialsId) {
        this.blackDuckSCACredentialsId = blackDuckSCACredentialsId;
        save();
    }

    @DataBoundSetter
    public void setDetectInstallationPath(String detectInstallationPath) {
        this.detectInstallationPath = detectInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setCoverityConnectUrl(String coverityConnectUrl) {
        this.coverityConnectUrl = coverityConnectUrl;
        save();
    }

    @DataBoundSetter
    public void setCoverityInstallationPath(String coverityInstallationPath) {
        this.coverityInstallationPath = coverityInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setBitbucketCredentialsId(String bitbucketCredentialsId) {
        this.bitbucketCredentialsId = bitbucketCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setGithubCredentialsId(String githubCredentialsId) {
        this.githubCredentialsId = githubCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setGitlabCredentialsId(String gitlabCredentialsId) {
        this.gitlabCredentialsId = gitlabCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setBridgeDownloadUrlForMac(String bridgeDownloadUrlForMac) {
        this.bridgeDownloadUrlForMac = bridgeDownloadUrlForMac;
        save();
    }

    @DataBoundSetter
    public void setBridgeDownloadUrlForWindows(String bridgeDownloadUrlForWindows) {
        this.bridgeDownloadUrlForWindows = bridgeDownloadUrlForWindows;
        save();
    }

    @DataBoundSetter
    public void setBridgeDownloadUrlForLinux(String bridgeDownloadUrlForLinux) {
        this.bridgeDownloadUrlForLinux = bridgeDownloadUrlForLinux;
        save();
    }

    @DataBoundSetter
    public void setBridgeDownloadVersion(String bridgeDownloadVersion) {
        this.bridgeDownloadVersion = bridgeDownloadVersion;
        save();
    }

    @DataBoundSetter
    public void setBridgeInstallationPath(String bridgeInstallationPath) {
        this.bridgeInstallationPath = bridgeInstallationPath;
        save();
    }

    @DataBoundSetter
    public void setNetworkAirGap(Boolean networkAirGap) {
        this.networkAirGap = networkAirGap;
        save();
    }

    @DataBoundSetter
    public void setPolarisServerUrl(String polarisServerUrl) {
        this.polarisServerUrl = polarisServerUrl;
        save();
    }

    @DataBoundSetter
    public void setPolarisCredentialsId(String polarisCredentialsId) {
        this.polarisCredentialsId = polarisCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setCoverityCredentialsId(String coverityCredentialsId) {
        this.coverityCredentialsId = coverityCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setSrmUrl(String srmUrl) {
        this.srmUrl = srmUrl;
        save();
    }

    @DataBoundSetter
    public void setSrmCredentialsId(String srmCredentialsId) {
        this.srmCredentialsId = srmCredentialsId;
        save();
    }

    @DataBoundSetter
    public void setSrmSCAInstallationPath(String srmSCAInstallationPath) {
        this.srmSCAInstallationPath = srmSCAInstallationPath;
    }

    @DataBoundSetter
    public void setSrmSASTInstallationPath(String srmSASTInstallationPath) {
        this.srmSASTInstallationPath = srmSASTInstallationPath;
    }

    public String getBlackDuckSCAUrl() {
        return blackDuckSCAUrl;
    }

    public String getDetectInstallationPath() {
        return detectInstallationPath;
    }

    public String getCoverityConnectUrl() {
        return coverityConnectUrl;
    }

    public String getCoverityInstallationPath() {
        return coverityInstallationPath;
    }

    public String getBridgeDownloadUrlForMac() {
        return bridgeDownloadUrlForMac;
    }

    public String getBridgeDownloadUrlForWindows() {
        return bridgeDownloadUrlForWindows;
    }

    public String getBridgeDownloadUrlForLinux() {
        return bridgeDownloadUrlForLinux;
    }

    public String getBridgeDownloadVersion() {
        return bridgeDownloadVersion;
    }

    public String getBridgeInstallationPath() {
        return bridgeInstallationPath;
    }

    public Boolean isNetworkAirGap() {
        return networkAirGap;
    }

    public String getPolarisServerUrl() {
        return polarisServerUrl;
    }

    public String getBlackDuckSCACredentialsId() {
        return blackDuckSCACredentialsId;
    }

    public String getCoverityCredentialsId() {
        return coverityCredentialsId;
    }

    public String getPolarisCredentialsId() {
        return polarisCredentialsId;
    }

    public String getBitbucketCredentialsId() {
        return bitbucketCredentialsId;
    }

    public String getGithubCredentialsId() {
        return githubCredentialsId;
    }

    public String getGitlabCredentialsId() {
        return gitlabCredentialsId;
    }

    public String getSrmUrl() {
        return srmUrl;
    }

    public String getSrmCredentialsId() {
        return srmCredentialsId;
    }

    public String getSrmSCAInstallationPath() {
        return srmSCAInstallationPath;
    }

    public String getSrmSASTInstallationPath() {
        return srmSASTInstallationPath;
    }

    private ListBoxModel getOptionsWithApiTokenCredentials() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(
                        ACL.SYSTEM2,
                        jenkins,
                        BaseStandardCredentials.class,
                        Collections.emptyList(),
                        ScanCredentialsHelper.API_TOKEN_CREDENTIALS);
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillBlackDuckSCACredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillPolarisCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillCoverityCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(
                        ACL.SYSTEM2,
                        jenkins,
                        BaseStandardCredentials.class,
                        Collections.emptyList(),
                        ScanCredentialsHelper.USERNAME_PASSWORD_CREDENTIALS);
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillSrmCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillBitbucketCredentialsIdItems() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return new StandardListBoxModel().includeEmptyValue();
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);
        return new StandardListBoxModel()
                .includeEmptyValue()
                .includeMatchingAs(
                        ACL.SYSTEM2,
                        jenkins,
                        BaseStandardCredentials.class,
                        Collections.emptyList(),
                        CredentialsMatchers.anyOf(
                                ScanCredentialsHelper.USERNAME_PASSWORD_CREDENTIALS,
                                ScanCredentialsHelper.API_TOKEN_CREDENTIALS));
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillGithubCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillGitlabCredentialsIdItems() {
        return getOptionsWithApiTokenCredentials();
    }

    @POST
    public FormValidation doTestBlackDuckSCAConnection(
            @QueryParameter("blackDuckSCAUrl") String blackDuckSCAUrl,
            @QueryParameter("blackDuckSCACredentialsId") String blackDuckSCACredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(blackDuckSCAUrl)) {
            return FormValidation.error("The Black Duck SCA URL must be specified");
        }
        if (Utility.isStringNullOrBlank(blackDuckSCACredentialsId)) {
            return FormValidation.error("The Black Duck SCA credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptBlackDuckSCAAuthentication(
                    blackDuckSCAUrl, blackDuckSCACredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    private String getValidationMessage(int statusCode) {
        String validationMessage;
        try {
            String statusPhrase = EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, Locale.ENGLISH);
            validationMessage = String.format("ERROR: Connection attempt returned %s %s", statusCode, statusPhrase);
        } catch (IllegalArgumentException ignored) {
            validationMessage = "ERROR: Connection could not be established.";
        }
        return validationMessage;
    }

    @POST
    public FormValidation doTestPolarisConnection(
            @QueryParameter("polarisServerUrl") String polarisServerUrl,
            @QueryParameter("polarisCredentialsId") String polarisCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(polarisServerUrl)) {
            return FormValidation.error("The Polaris server url must be specified");
        }
        if (Utility.isStringNullOrBlank(polarisCredentialsId)) {
            return FormValidation.error("The Polaris credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptPolarisAuthentication(
                    polarisServerUrl, polarisCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    @POST
    public FormValidation doTestCoverityConnection(
            @QueryParameter("coverityConnectUrl") String coverityConnectUrl,
            @QueryParameter("coverityCredentialsId") String coverityCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(coverityConnectUrl)) {
            return FormValidation.error("The Coverity connect url must be specified");
        }
        if (Utility.isStringNullOrBlank(coverityCredentialsId)) {
            return FormValidation.error("The Coverity credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptCoverityAuthentication(
                    coverityConnectUrl, coverityCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    @POST
    public FormValidation doTestSrmConnection(
            @QueryParameter("srmUrl") String srmUrl, @QueryParameter("srmCredentialsId") String srmCredentialsId) {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return FormValidation.warning(LogMessages.JENKINS_INSTANCE_MISSING_WARNING);
        }
        jenkins.checkPermission(Jenkins.ADMINISTER);

        if (Utility.isStringNullOrBlank(srmUrl)) {
            return FormValidation.error("The SRM server url must be specified");
        }
        if (Utility.isStringNullOrBlank(srmCredentialsId)) {
            return FormValidation.error("The SRM credentials must be specified");
        }

        try {
            AuthenticationSupport authenticationSupport = new AuthenticationSupport();
            HttpResponse response = authenticationSupport.attemptSrmAuthentication(
                    srmUrl, srmCredentialsId, CONNECTION_TIMEOUT_IN_SECONDS);

            if (response.getCode() != HttpURLConnection.HTTP_OK) {
                String validationMessage = getValidationMessage(response.getCode());

                return FormValidation.error(String.join(" ", validationMessage));
            }
        } catch (Exception e) {
            return FormValidation.error(AUTHORIZATION_FAILURE
                    + getFormattedExceptionMessage(e.getCause().getMessage()));
        }

        return FormValidation.ok(CONNECTION_SUCCESSFUL);
    }

    private String getFormattedExceptionMessage(String message) {
        Pattern pattern = Pattern.compile("failed: (.*)");
        Matcher matcher = pattern.matcher(message);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return message;
        }
    }
}
