package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.blackducksca.*;
import io.jenkins.plugins.security.scan.input.detect.*;
import java.util.Map;

public class DetectParametersService {

    public Detect prepareDetectObject(Map<String, Object> detectParameters) {
        Detect detect = new Detect();

        setScanFull(detectParameters, detect);
        setInstallDirectory(detectParameters, detect);
        setDownloadUrl(detectParameters, detect);
        setSearchDepth(detectParameters, detect);
        setConfigPath(detectParameters, detect);
        setBlackDuckArgs(detectParameters, detect);
        setExecutionPath(detectParameters, detect);

        return detect;
    }

    private void setScanFull(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_SCAN_FULL_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_SCAN_FULL_KEY)
                    .toString()
                    .trim();
            if (Utility.isBoolean(value)) {
                Scan scan = new Scan();
                scan.setFull(Boolean.parseBoolean(value));
                detect.setScan(scan);
            }
        }
    }

    private void setInstallDirectory(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)
                    .toString()
                    .trim();
            Install install = new Install();
            install.setDirectory(value);
            detect.setInstall(install);
        }
    }

    private void setDownloadUrl(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY)
                    .toString()
                    .trim();
            Download download = new Download();
            download.setUrl(value);
            detect.setDownload(download);
        }
    }

    private void setSearchDepth(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY)) {
            String searchDepth = scanParameters
                    .get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY)
                    .toString()
                    .trim();
            if (!searchDepth.isBlank()) {
                Search search = new Search();
                search.setDepth(Integer.parseInt(searchDepth));
                detect.setSearch(search);
            }
        }
    }

    private void setConfigPath(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_CONFIG_PATH_KEY)) {
            String configPath = scanParameters
                    .get(ApplicationConstants.DETECT_CONFIG_PATH_KEY)
                    .toString()
                    .trim();
            if (!configPath.isBlank()) {
                Config config = new Config();
                config.setPath(configPath);
                detect.setConfig(config);
            }
        }
    }

    private void setBlackDuckArgs(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_ARGS_KEY)) {
            String detectArgs = scanParameters
                    .get(ApplicationConstants.DETECT_ARGS_KEY)
                    .toString()
                    .trim();
            if (!detectArgs.isBlank()) {
                detect.setArgs(detectArgs);
            }
        }
    }

    private void setExecutionPath(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_EXECUTION_PATH_KEY)) {
            String installationPath = scanParameters
                    .get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY)
                    .toString()
                    .trim();
            if (!installationPath.isBlank()) {
                Execution execution = new Execution();
                execution.setPath(installationPath);
                detect.setExecution(execution);
            }
        }
    }
}
