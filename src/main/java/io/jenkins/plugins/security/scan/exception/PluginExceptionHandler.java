package io.jenkins.plugins.security.scan.exception;

import java.io.Serial;

public class PluginExceptionHandler extends Exception {
    @Serial
    private static final long serialVersionUID = 3172941819259598261L;

    private int code;

    public PluginExceptionHandler() {
        super();
    }

    public PluginExceptionHandler(String message) {
        super(message);
    }

    public PluginExceptionHandler(int code) {
        this.code = code;
    }

    public PluginExceptionHandler(int code, String message) {
        super(message);
        this.code = code;
    }

    public PluginExceptionHandler(Throwable cause) {
        super(cause);
    }

    public PluginExceptionHandler(String message, Throwable cause) {
        super(message, cause);
    }

    public int getCode() {
        return code;
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
