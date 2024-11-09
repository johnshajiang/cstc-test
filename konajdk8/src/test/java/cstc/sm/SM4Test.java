package cstc.sm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static cstc.util.Util.toBytes;

public class SM4Test {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("10000000000000000000000000000001");
    private static final byte[] GCM_IV = toBytes("100000000000000000000001");

    private static final byte[] MESSAGE = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    @Test
    public void testCBCMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCTRMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testECBMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testGCMMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(128, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }
}
