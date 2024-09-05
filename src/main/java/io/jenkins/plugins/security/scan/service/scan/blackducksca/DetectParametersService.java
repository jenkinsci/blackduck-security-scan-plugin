package io.jenkins.plugins.security.scan.service.scan.blackducksca;

import io.jenkins.plugins.security.scan.global.ApplicationConstants;
import io.jenkins.plugins.security.scan.global.Utility;
import io.jenkins.plugins.security.scan.input.blackducksca.*;
import io.jenkins.plugins.security.scan.input.detect.*;
import java.util.Map;

public class DetectParametersService {

    public Detect prepareDetectObject(Map<String, Object> detectParameters) {
        Detect detect = null;

        detect = setScanFull(detectParameters, detect);
        detect = setInstallDirectory(detectParameters, detect);
        detect = setDownloadUrl(detectParameters, detect);
        detect = setSearchDepth(detectParameters, detect);
        detect = setConfigPath(detectParameters, detect);
        detect = setBlackDuckArgs(detectParameters, detect);
        detect = setExecutionPath(detectParameters, detect);

        return detect;
    }

    private Detect setScanFull(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_SCAN_FULL_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_SCAN_FULL_KEY)
                    .toString()
                    .trim();
            if (Utility.isBoolean(value)) {
                if (detect == null) {
                    detect = new Detect();
                }
                Scan scan = new Scan();
                scan.setFull(Boolean.parseBoolean(value));
                detect.setScan(scan);
            }
        }
        return detect;
    }

    private Detect setInstallDirectory(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_INSTALL_DIRECTORY_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                Install install = new Install();
                install.setDirectory(value);
                detect.setInstall(install);
            }
        }
        return detect;
    }

    private Detect setDownloadUrl(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY)) {
            String value = scanParameters
                    .get(ApplicationConstants.DETECT_DOWNLOAD_URL_KEY)
                    .toString()
                    .trim();
            if (!value.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                Download download = new Download();
                download.setUrl(value);
                detect.setDownload(download);
            }
        }
        return detect;
    }

    private Detect setSearchDepth(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY)) {
            String searchDepth = scanParameters
                    .get(ApplicationConstants.DETECT_SEARCH_DEPTH_KEY)
                    .toString()
                    .trim();
            if (!searchDepth.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                Search search = new Search();
                search.setDepth(Integer.parseInt(searchDepth));
                detect.setSearch(search);
            }
        }
        return detect;
    }

    private Detect setConfigPath(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_CONFIG_PATH_KEY)) {
            String configPath = scanParameters
                    .get(ApplicationConstants.DETECT_CONFIG_PATH_KEY)
                    .toString()
                    .trim();
            if (!configPath.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                Config config = new Config();
                config.setPath(configPath);
                detect.setConfig(config);
            }
        }
        return detect;
    }

    private Detect setBlackDuckArgs(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_ARGS_KEY)) {
            String detectArgs = scanParameters
                    .get(ApplicationConstants.DETECT_ARGS_KEY)
                    .toString()
                    .trim();
            if (!detectArgs.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                detect.setArgs(detectArgs);
            }
        }
        return detect;
    }

    private Detect setExecutionPath(Map<String, Object> scanParameters, Detect detect) {
        if (scanParameters.containsKey(ApplicationConstants.DETECT_EXECUTION_PATH_KEY)) {
            String installationPath = scanParameters
                    .get(ApplicationConstants.DETECT_EXECUTION_PATH_KEY)
                    .toString()
                    .trim();
            if (!installationPath.isBlank()) {
                if (detect == null) {
                    detect = new Detect();
                }
                Execution execution = new Execution();
                execution.setPath(installationPath);
                detect.setExecution(execution);
            }
        }
        return detect;
    }
}
