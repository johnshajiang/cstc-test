
package cstc.util;

public class Util {

    public static byte[] toBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] data(int size, byte b) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = b;
        }
        return data;
    }

    public static byte[] data(int size) {
        return data(size, (byte) 'a');
    }

    public static byte[] dataKB(int sizeInKB) {
        return data(sizeInKB * 1024);
    }

    public static byte[] dataMB(int sizeInMB) {
        return dataKB(sizeInMB * 1024);
    }
}
