package com.ospysin.tools.probes;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Custom X.509 TrustManager that captures the server certificate chain and evaluates
 * trust status without aborting the TLS handshake on untrusted, expired, or self-signed certificates.
 */
public class InspectionTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager defaultTrustManager;
    private X509Certificate[] serverChain;
    private boolean trustVerified = false;
    private String trustFailureReason = null;

    public InspectionTrustManager() {
        X509ExtendedTrustManager extendedTm = null;
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509ExtendedTrustManager ext) {
                    extendedTm = ext;
                    break;
                } else if (tm instanceof X509TrustManager standard) {
                    extendedTm = wrapStandard(standard);
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        this.defaultTrustManager = extendedTm;
    }

    public InspectionTrustManager(X509ExtendedTrustManager defaultTrustManager) {
        this.defaultTrustManager = defaultTrustManager;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        evaluateServerChain(chain, () -> {
            if (defaultTrustManager != null) {
                defaultTrustManager.checkServerTrusted(chain, authType);
            }
        });
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        evaluateServerChain(chain, () -> {
            if (defaultTrustManager != null) {
                defaultTrustManager.checkServerTrusted(chain, authType, socket);
            }
        });
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        evaluateServerChain(chain, () -> {
            if (defaultTrustManager != null) {
                defaultTrustManager.checkServerTrusted(chain, authType, engine);
            }
        });
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return defaultTrustManager != null ? defaultTrustManager.getAcceptedIssuers() : new X509Certificate[0];
    }

    public X509Certificate[] getServerChain() {
        return serverChain;
    }

    public boolean isTrustVerified() {
        return trustVerified;
    }

    public String getTrustFailureReason() {
        return trustFailureReason;
    }

    private void evaluateServerChain(X509Certificate[] chain, CheckedRunnable verification) {
        this.serverChain = chain != null ? chain.clone() : null;
        if (defaultTrustManager == null) {
            this.trustVerified = false;
            this.trustFailureReason = "Default TrustManager unavailable";
            return;
        }

        try {
            verification.run();
            this.trustVerified = true;
            this.trustFailureReason = null;
        } catch (CertificateException e) {
            this.trustVerified = false;
            this.trustFailureReason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            // Do NOT rethrow CertificateException, allowing TLS probe handshake to complete successfully!
        } catch (Exception e) {
            this.trustVerified = false;
            this.trustFailureReason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static X509ExtendedTrustManager wrapStandard(X509TrustManager standard) {
        return new X509ExtendedTrustManager() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                standard.checkServerTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                standard.checkServerTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                standard.checkServerTrusted(chain, authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                standard.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                standard.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                standard.checkClientTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return standard.getAcceptedIssuers();
            }
        };
    }
}
