package cstc.sm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

import static cstc.util.Util.toBytes;

public class SM3Test {

    private static final byte[] MESSAGE = toBytes("616263");
    private static final byte[] DIGEST = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] MAC = toBytes("4d2e8eefcfaa97b2bea04cda000823a4f2e6e264cf7a819d67117ad12cc9a8af");

    @Test
    public void testDigest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3");
        byte[] digest = md.digest(MESSAGE);
        Assertions.assertArrayEquals(DIGEST, digest);
    }

    @Test
    public void testMac() throws Exception {
        Mac hmacSM3 = Mac.getInstance("HmacSM3");
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        hmacSM3.init(keySpec);
        byte[] mac = hmacSM3.doFinal(MESSAGE);
        Assertions.assertArrayEquals(MAC, mac);
    }
}
