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
@BenchmarkMode(Mode.Throughput)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class TLSPerfTest {

    protected final static Cert[] TRUSTED_CERTS = {
            Cert.CA_CERT};

    protected final static Cert[] EE_CERTS = {
            Cert.EE_CERT, Cert.EE_CERT};

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

    @Param({"TLSv1.3", "TLSv1.2"})
    String protocol;

    @Param({"false", "true"})
    boolean resume;

    @Setup(Level.Trial)
    public void init() throws Exception {
        serverContext = createServerSSLContext();
        clientContext = createClientSSLContext();
    }

    protected SSLContext createClientSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, EE_CERTS,
                getClientContextParameters());
    }

    /*
     * Create an instance of SSLContext for server use.
     */
    protected SSLContext createServerSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, EE_CERTS,
                getServerContextParameters());
    }

    protected ContextParameters getClientContextParameters() {
        return new ContextParameters("TLS",
                TrustManagerFactory.getDefaultAlgorithm(),
                KeyManagerFactory.getDefaultAlgorithm());
    }

    /*
     * Get the server side parameters of SSLContext.
     */
    protected ContextParameters getServerContextParameters() {
        return new ContextParameters("TLS",
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

        clientEngine.setEnabledProtocols(new String[] {protocol});

        String cipherSuite = null;
        if ("TLSv1.3".equals(protocol)) {
            cipherSuite = "TLS_AES_128_GCM_SHA256";
        } else {
            cipherSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        }
        clientEngine.setEnabledCipherSuites(new String[] {cipherSuite});
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
                "MIIBuTCCAV6gAwIBAgIUKmWv3/Tfg1gkaPNURtNO0/SkjwkwCgYIKoZIzj0EAwIw\n" +
                "FzEVMBMGA1UEAwwMY2EtcDI1NmVjZHNhMB4XDTIxMDkxMTIwMTUxNloXDTMxMDkw\n" +
                "OTIwMTUxNlowJDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTBZ\n" +
                "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABI8zS78F3eCOnknb9CUI6taz7YXgAEPp\n" +
                "V03N11zF10EN1jaf7Zw33OFSKCEPaCFvvmV5RV57Q9+kgoS3NqR8kiajezB5MB0G\n" +
                "A1UdDgQWBBRwFJlygX8L0akeiDbS5kiXj4e4VTAfBgNVHSMEGDAWgBSuBXJlqm8G\n" +
                "BJPn1y8OACYcWIhDzzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAW\n" +
                "BgNVHSUBAf8EDDAKBggrBgEFBQcDCTAKBggqhkjOPQQDAgNJADBGAiEAt6X+tCHd\n" +
                "oFAJ4qSwCGZ3Y9QiHtKy4bKRhMdFpZxAIWICIQCe4lH45iSB93JDQ6uQbjjfdjSh\n" +
                "uWUvOaC8egBzIpFaFQ==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgl8tSMRCrTmAjuddY\n" +
                "5ATvA35iDKydBgVQkLPLpxjmTFChRANCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7Rl\n" +
                "sFspKwF5LMxkcYMblZXjlUYVhnpNF3N/x2knleNfrXrdTTR3Yv2MIMGQ"),
        EE_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkzCCATmgAwIBAgIUfMbvyf8bQEpMEYXnFNuCbGFXMSUwCgYIKoZIzj0EAwIw\n" +
                "JDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTAeFw0yMTA5MTEy\n" +
                "MDE1MTZaFw0zMTA5MDkyMDE1MTZaMCsxKTAnBgNVBAMMIGVlLXAyNTZlY2RzYS1w\n" +
                "MjU2ZWNkc2EtcDI1NmVjZHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtfjR\n" +
                "0wNCRllUUk1sGpGsriOEJBCtWKjCgDr4FA8F4KmYGVEOKeJ90eJcbgNa0T1eyJFE\n" +
                "CGw/DkpXONbejD9Bc6NCMEAwHQYDVR0OBBYEFPLWXqOSjnjRwO7LqoLSaGg+oMhg\n" +
                "MB8GA1UdIwQYMBaAFHAUmXKBfwvRqR6INtLmSJePh7hVMAoGCCqGSM49BAMCA0gA\n" +
                "MEUCIQCDDTDSpHSdfdC2SkUwXDvuglW5dmGPrFVk6JcNdCUIcgIgYwbGn7MVijT7\n" +
                "g5qUdXF/YsUEFsTZage7fAltZ7AcARU=\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZY/ebcIPzj+r0Jf7\n" +
                "xiH0qu5fsCLlkGTlgnMBuaDQqOahRANCAAS1+NHTA0JGWVRSTWwakayuI4QkEK1Y\n" +
                "qMKAOvgUDwXgqZgZUQ4p4n3R4lxuA1rRPV7IkUQIbD8OSlc41t6MP0Fz");

        final String keyAlgo = "EC";
        final String certStr;
        final String privKeyStr;

        Cert(String certStr, String privKeyStr) {
            this.certStr = certStr;
            this.privKeyStr = privKeyStr;
        }
    }
}
