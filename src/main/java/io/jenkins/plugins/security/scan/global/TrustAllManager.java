package io.jenkins.plugins.security.scan.global;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class TrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        // No implementation needed for trusting all certificates
        // This method is intentionally left blank to trust all client certificates
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        // No implementation needed for trusting all certificates
        // This method is intentionally left blank to trust all client certificates
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}
