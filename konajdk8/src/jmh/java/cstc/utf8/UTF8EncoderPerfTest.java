package cstc.utf8;

import org.openjdk.jmh.annotations.*;

import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@Warmup(iterations = 2, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 10, timeUnit = TimeUnit.SECONDS)
@OutputTimeUnit(TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)

/*
 * Test convert between UTF8 and String with hadoop Text API
 */
public class UTF8EncoderPerfTest {

    static String base;
    static String mixed;
    static final CharsetEncoder encoder;
    static {
        encoder = StandardCharsets.UTF_8.newEncoder();
        base = "abcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyz"
                    + "abcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyz"
                    + "abcdefghijklmnopqrstuvmxyz";
        for (int i = 0; i < 9; i++) {
            base += base;
        }
        mixed = "a腾讯bcÓî虚拟机kona";
        for (int i = 0; i < 10; i++) {
            mixed += mixed;
        }
    }

    @Param({"4096"})
    public int len = 0;
    @Param({"100"})
    public int count = 0;

    public char[][] encode_inputs;
    public char[][] mixed_encode_inputs;
    public char[][] major_encode_inputs;

    @Benchmark
    public void testEncode() throws Exception {
        for (int i = 0; i < count; i++) {
            encoder.encode(CharBuffer.wrap(major_encode_inputs[i], 0, major_encode_inputs[i].length));
        }
    }

    @Setup
    public void prepare() {
        encode_inputs = new char[count][];
        mixed_encode_inputs = new char[count][];
        major_encode_inputs = new char[count][];

        for (int i = 0; i < count; i++) {
            String strBase = base.substring(i, i + len);
            encode_inputs[i] = new char[strBase.length()];
            strBase.getChars(0, strBase.length(), encode_inputs[i], 0);

            String str = mixed.substring(i, i + len);
            mixed_encode_inputs[i] = new char[str.length()];
            str.getChars(0, str.length(), mixed_encode_inputs[i], 0);

            str = strBase.substring(0, len / 2) + "\u4e2d\u56fd" + strBase.substring(len / 2);
            major_encode_inputs[i] = new char[str.length()];
            str.getChars(0, str.length(), major_encode_inputs[i], 0);
        }
    }
}
