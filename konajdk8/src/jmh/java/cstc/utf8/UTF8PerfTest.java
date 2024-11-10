package cstc.utf8;

import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@BenchmarkMode(Mode.Throughput)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC", "-XX:+IgnoreUnrecognizedVMOptions", "-XX:+UseUTF8UTF16Intrinsics"})
@Threads(1)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class UTF8PerfTest {

    private static final String TEXT = "0123456789abcdef中0123456789abcdef";
    private static final byte[] TEXT_B = TEXT.getBytes(StandardCharsets.UTF_8);

    private static final String ENCODE_DATA = encodeData(1024);
    private static final byte[] DECODE_DATA = decodeData(1024);

    public static String encodeData(int size) {
        StringBuilder data = new StringBuilder();
        for (int i = 0; i < size; i++) {
            data.append(TEXT);
        }
        return data.toString();
    }

    public static byte[] decodeData(int size) {
        byte[] data = new byte[size * TEXT_B.length];
        for (int i = 0; i < size; i++) {
            System.arraycopy(TEXT_B, 0, data, i * TEXT_B.length, TEXT_B.length);
        }
        return data;
    }

    @Benchmark
    public byte[] encode() {
        return ENCODE_DATA.getBytes(StandardCharsets.UTF_8);
    }

    @Benchmark
    public String decode() {
        return new String(DECODE_DATA);
    }
}
