package io.jenkins.plugins.security.scan.global;

import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import java.io.File;
import jenkins.MasterToSlaveFileCallable;

public class OsNameTask extends MasterToSlaveFileCallable<String> implements FilePath.FileCallable<String> {
    @Override
    public String invoke(File workspace, VirtualChannel channel) {
        return System.getProperty("os.name").toLowerCase();
    }
}
