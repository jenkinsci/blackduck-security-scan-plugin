package io.jenkins.plugins.security.scan.global;

import hudson.remoting.VirtualChannel;
import java.io.File;
import jenkins.MasterToSlaveFileCallable;

public class HomeDirectoryTask extends MasterToSlaveFileCallable<String> {
    private final String separator;

    public HomeDirectoryTask(String separator) {
        this.separator = separator;
    }

    @Override
    public String invoke(File f, VirtualChannel channel) {
        return System.getProperty("user.home").concat(separator).concat(ApplicationConstants.DEFAULT_DIRECTORY_NAME);
    }
}
