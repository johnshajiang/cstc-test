/*
 * Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package cstc.ssl;

import org.openjdk.jmh.annotations.*;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class TLCPPerfTest {

    protected final static Cert[] TRUSTED_CERTS = {
            Cert.CA_CERT};

    protected final static Cert[] SERVER_CERTS = {
            Cert.SERVER_SIGN_CERT, Cert.SERVER_ENC_CERT};
    protected final static Cert[] CLIENT_CERTS = {
            Cert.CLIENT_SIGN_CERT, Cert.CLIENT_ENC_CERT};

    private SSLContext serverContext;
    private SSLContext clientContext;

    private SSLEngine clientEngine;
    private ByteBuffer clientOut = ByteBuffer.allocate(5);
    private ByteBuffer clientIn = ByteBuffer.allocate(1 << 15);

    private SSLEngine serverEngine;
    private ByteBuffer serverOut = ByteBuffer.allocate(5);
    private ByteBuffer serverIn = ByteBuffer.allocate(1 << 15);

    private ByteBuffer cTOs = ByteBuffer.allocateDirect(1 << 16);
    private ByteBuffer sTOc = ByteBuffer.allocateDirect(1 << 16);

    @Param({"TLCPv1.1"})
    String protocol;

    @Param({"false", "true"})
    boolean resume;

    @Setup(Level.Trial)
    public void init() throws Exception {
        serverContext = createServerSSLContext();
        clientContext = createClientSSLContext();
    }

    protected SSLContext createClientSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, CLIENT_CERTS,
                getClientContextParameters());
    }

    /*
     * Create an instance of SSLContext for server use.
     */
    protected SSLContext createServerSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, SERVER_CERTS,
                getServerContextParameters());
    }

    protected ContextParameters getClientContextParameters() {
        return new ContextParameters("TLCP",
                TrustManagerFactory.getDefaultAlgorithm(),
                KeyManagerFactory.getDefaultAlgorithm());
    }

    /*
     * Get the server side parameters of SSLContext.
     */
    protected ContextParameters getServerContextParameters() {
        return new ContextParameters("TLCP",
                TrustManagerFactory.getDefaultAlgorithm(),
                KeyManagerFactory.getDefaultAlgorithm());
    }

    public static SSLContext createSSLContext(
            Cert[] trustedCerts,
            Cert[] endEntityCerts,
            ContextParameters params) throws Exception {

        KeyStore ts = null;     // trust store
        KeyStore ks = null;     // key store
        char passphrase[] = "passphrase".toCharArray();

        // Generate certificate from cert string.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Import the trused certs.
        ByteArrayInputStream is;
        if (trustedCerts != null && trustedCerts.length != 0) {
            ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);

            Certificate[] trustedCert = new Certificate[trustedCerts.length];
            for (int i = 0; i < trustedCerts.length; i++) {
                is = new ByteArrayInputStream(trustedCerts[i].certStr.getBytes());
                try {
                    trustedCert[i] = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                ts.setCertificateEntry(
                        "trusted-cert-" + trustedCerts[i].name(), trustedCert[i]);
            }
        }

        // Import the key materials.
        if (endEntityCerts != null && endEntityCerts.length != 0) {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);

            for (int i = 0; i < endEntityCerts.length; i++) {
                // generate the private key.
                PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
                        Base64.getMimeDecoder().decode(endEntityCerts[i].privKeyStr));
                KeyFactory kf = KeyFactory.getInstance(
                        endEntityCerts[i].keyAlgo);
                PrivateKey priKey = kf.generatePrivate(priKeySpec);

                // generate certificate chain
                is = new ByteArrayInputStream(
                        endEntityCerts[i].certStr.getBytes());
                Certificate keyCert = null;
                try {
                    keyCert = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                Certificate[] chain = new Certificate[] { keyCert };

                // import the key entry.
                ks.setKeyEntry("cert-" + endEntityCerts[i].name(),
                        priKey, passphrase, chain);
            }
        }

        // Create an SSLContext object.
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(params.tmAlgorithm);
        tmf.init(ts);

        SSLContext context = SSLContext.getInstance(params.contextProtocol);
        if (endEntityCerts != null && endEntityCerts.length != 0 && ks != null) {
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(params.kmAlgorithm);
            kmf.init(ks, passphrase);

            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } else {
            context.init(null, tmf.getTrustManagers(), null);
        }

        return context;
    }

    protected static final class ContextParameters {
        final String contextProtocol;
        final String tmAlgorithm;
        final String kmAlgorithm;

        ContextParameters(String contextProtocol,
                          String tmAlgorithm, String kmAlgorithm) {

            this.contextProtocol = contextProtocol;
            this.tmAlgorithm = tmAlgorithm;
            this.kmAlgorithm = kmAlgorithm;
        }
    }

    /**
     * This benchmark measures the time needed to perform a TLS handshake.
     * Data is exchanged using a pair of ByteBuffers.
     * The client and the server both operate on the same thread.
     */
    @Benchmark
    public SSLSession doHandshake() throws Exception {
        createSSLEngines();

        boolean isCtoS = true;
        for (;;) {
            HandshakeStatus result;
            if (isCtoS) {
                result = checkResult(clientEngine,
                        clientEngine.wrap(clientOut, cTOs));
                cTOs.flip();
                checkResult(serverEngine, serverEngine.unwrap(cTOs, serverIn));
                cTOs.compact();
                if (result == HandshakeStatus.NEED_UNWRAP) {
                    isCtoS = false;
                } else if (result == HandshakeStatus.FINISHED) {
                    break;
                } else if (result != HandshakeStatus.NEED_WRAP) {
                    throw new Exception("Unexpected result "+result);
                }
            } else {
                result = checkResult(serverEngine,
                        serverEngine.wrap(serverOut, sTOc));
                sTOc.flip();
                checkResult(clientEngine,
                        clientEngine.unwrap(sTOc, clientIn));
                sTOc.compact();
                if (result == HandshakeStatus.NEED_UNWRAP) {
                    isCtoS = true;
                } else if (result == HandshakeStatus.FINISHED) {
                    break;
                } else if (result != HandshakeStatus.NEED_WRAP) {
                    throw new Exception("Unexpected result "+result);
                }
            }
        }

        SSLSession session = clientEngine.getSession();
        if (resume) {
            // TLS 1.3 needs another wrap/unwrap to deliver a session ticket
            serverEngine.wrap(serverOut, sTOc);
            sTOc.flip();
            clientEngine.unwrap(sTOc, clientIn);
            sTOc.compact();
        } else {
            // invalidate TLS1.2 session. TLS 1.3 doesn't care
            session.invalidate();
        }
        return session;
    }

    private void createSSLEngines() {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS
         * handshake.
         */
        serverEngine = serverContext.createSSLEngine();
        serverEngine.setUseClientMode(false);

        /*
         * Similar to above, but using client mode instead.
         */
        clientEngine = clientContext.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[] {"TLCPv1.1"});
        clientEngine.setEnabledCipherSuites(new String[] { "TLCP_ECC_SM4_GCM_SM3" });
    }

    private HandshakeStatus checkResult(SSLEngine engine, SSLEngineResult result) {
        HandshakeStatus hsStatus = result.getHandshakeStatus();

        if (hsStatus == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                runnable.run();
            }
            hsStatus = engine.getHandshakeStatus();
        }
        return hsStatus;
    }

    public enum Cert {

        CA_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBjDCCATKgAwIBAgIUc1kBltJcsvucxFYD+CzKcGvuNHowCgYIKoEcz1UBg3Uw\n" +
                "EjEQMA4GA1UEAwwHdGxjcC1jYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgxMTU2\n" +
                "MzhaMBUxEzARBgNVBAMMCnRsY3AtaW50Y2EwWTATBgcqhkjOPQIBBggqgRzPVQGC\n" +
                "LQNCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7RlsFspKwF5LMxkcYMblZXjlUYVhnpN\n" +
                "F3N/x2knleNfrXrdTTR3Yv2MIMGQo2MwYTAdBgNVHQ4EFgQURS/dNZJ+d0Sel9TW\n" +
                "vGNYGWnxTb4wHwYDVR0jBBgwFoAUQI8lwKZzxP/OpobF4UNyPG3JiocwDwYDVR0T\n" +
                "AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIhAI79\n" +
                "0T0rhbYCdqdGqbYxidgyr1XRpXncwRqmx7a+IDkvAiBDPtfFfB/UiwO4wBLqxwJO\n" +
                "+xEdTF+d/Wfro9fxSnrqEw==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgl8tSMRCrTmAjuddY\n" +
                "5ATvA35iDKydBgVQkLPLpxjmTFChRANCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7Rl\n" +
                "sFspKwF5LMxkcYMblZXjlUYVhnpNF3N/x2knleNfrXrdTTR3Yv2MIMGQ"),
        SERVER_SIGN_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkjCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwMwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3Atc2VydmVyLXNpZ24wWTATBgcqhkjOPQIB\n" +
                "BggqgRzPVQGCLQNCAARYT1t4ecS5pLkQlA9smyxe1tictMdl/x4AbO8nI07CHjXK\n" +
                "HPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuODo2AwXjAdBgNVHQ4EFgQUIerW\n" +
                "JjprHQfhD6ETgBX0G8dWWGswHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
                "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSAAw\n" +
                "RQIgW88b4/7Rgj0QVkHR49zINniwxdjotBRkSwdKNkVtt7YCIQCkjttpnM3HU0v7\n" +
                "NYFodEcndjXj9RDGujYO9NxgegXpSg==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg6wAH+egoZkKS3LKi\n" +
                "0okzJSYrn/yRVhNfmdhySuJic5ahRANCAARYT1t4ecS5pLkQlA9smyxe1tictMdl\n" +
                "/x4AbO8nI07CHjXKHPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuOD"),
        SERVER_ENC_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkDCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwYwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3Atc2VydmVyLWVuYzBZMBMGByqGSM49AgEG\n" +
                "CCqBHM9VAYItA0IABAQbatb13gJL3zt1B8U5LoheRJ+4XnRpqIQ5Osx0VDk4UW25\n" +
                "8aLlU96bf3onvnHThpa9GwHbY5BpYsMP1hS+1kCjYDBeMB0GA1UdDgQWBBQ0KNMH\n" +
                "KtXGecDXiEtTjCfhpDh5CDAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
                "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNHADBE\n" +
                "AiAD2eC+F7kTZGbH2lHG7ZTOzx62OYo1MSn31+hKHfbZ9AIgazWIQMJ0MQfn/qX5\n" +
                "z0Ez8iVqyDxZyHIOFjbr1DZEQEk=\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqFilR+zUyRQWREb+\n" +
                "rb5uIldK/bPE1l20DzNpuMt55VehRANCAAQEG2rW9d4CS987dQfFOS6IXkSfuF50\n" +
                "aaiEOTrMdFQ5OFFtufGi5VPem396J75x04aWvRsB22OQaWLDD9YUvtZA"),
        CLIENT_SIGN_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkzCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwQwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3AtY2xpZW50LXNpZ24wWTATBgcqhkjOPQIB\n" +
                "BggqgRzPVQGCLQNCAASPBt+HBVc3bmQkKHNR6EQVdSS905HiiOphVGuDwHrMpzUm\n" +
                "Qh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefXo2AwXjAdBgNVHQ4EFgQUM7U5\n" +
                "/ErJ5ZdOZVUGvFqUAQyW70AwHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
                "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSQAw\n" +
                "RgIhANKxFf6vSIWsACuxWGCG4/uJmc82jAIKCCrWH09KIt5kAiEA0XGSRL+mZu2L\n" +
                "1jf5zKhE6ASDdV634fDEknKcsLkuvvU=\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgulutgxQDiBzTCYiu\n" +
                "adobFrKgK/umEjLmUKTUjUKXVI+hRANCAASPBt+HBVc3bmQkKHNR6EQVdSS905Hi\n" +
                "iOphVGuDwHrMpzUmQh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefX"),
        CLIENT_ENC_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwcwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3AtY2xpZW50LWVuYzBZMBMGByqGSM49AgEG\n" +
                "CCqBHM9VAYItA0IABF8BHUkVbNgU/EmoZlSAWbPcMHuV2LZU62AJElRf/ZasTmMH\n" +
                "uhdtOAnoIkvuBh+yJZBjKM/0avFAbCDY5Mjo8RKjYDBeMB0GA1UdDgQWBBSjHJvH\n" +
                "aqrfqkgfyR7af6BSlPyXHTAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
                "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNIADBF\n" +
                "AiEAwBlUP46RdSR2eBgMe30DcMXDUcdv/W1stRGWS0znQB0CIG2pC+yOAe+R97JW\n" +
                "Nvbb8xtPrMYkjrU5emCH2H0a6eHz\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqrW1N+3YxmSDz7KX\n" +
                "dCH238n62DR6/3Fw4723EaMFh2GhRANCAARfAR1JFWzYFPxJqGZUgFmz3DB7ldi2\n" +
                "VOtgCRJUX/2WrE5jB7oXbTgJ6CJL7gYfsiWQYyjP9GrxQGwg2OTI6PES");

        final String keyAlgo = "EC";
        final String certStr;
        final String privKeyStr;

        Cert(String certStr, String privKeyStr) {
            this.certStr = certStr;
            this.privKeyStr = privKeyStr;
        }
    }
}
