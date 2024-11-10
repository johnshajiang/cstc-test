package cstc.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class SM2Test {

    private final static byte[] MESSAGE = "message".getBytes();

    @Test
    public void testKeyPairGen() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("curveSM2"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
        Assertions.assertTrue(priKey.getParams().toString().contains("curveSM2"));
        Assertions.assertTrue(pubKey.getParams().toString().contains("curveSM2"));
    }

    @Test
    public void testCipher() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("curveSM2"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("SM2");

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testSignature() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("curveSM2"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signer = Signature.getInstance("SM2");
        signer.initSign(keyPair.getPrivate());

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }
}
