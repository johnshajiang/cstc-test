package cstc.utf8;

import org.openjdk.jmh.annotations.*;

import org.apache.hadoop.io.Text;

import java.nio.ByteBuffer;
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
public class UTF8DecoderPerfTest {

    static String base;
    static final CharsetDecoder decoder;
    static {
        decoder = StandardCharsets.UTF_8.newDecoder();
        base = "abcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyz"
                    + "abcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyzabcdefghijklmnopqrstuvmxyz"
                    + "abcdefghijklmnopqrstuvmxyz";
        for (int i = 0; i < 9; i++) {
            base += base;
        }
    }

    @Param({"4096"})
    public int len = 0;
    @Param({"100"})
    public int count = 0;

    public String[] mixed_encode_inputs;
    public Text[] mixed_decode_inputs;
    public byte[][] utf8_arrays_mixed;

    @Benchmark
    public void testDecode() throws Exception {
        for (int i = 0; i < count; i++) {
            mixed_decode_inputs[i].toString();
        }
    }

    @Benchmark
    public void testDecodeMixedASCII() throws Exception {
        for (int i = 0; i < count; i++) {
            decoder.decode(ByteBuffer.wrap(utf8_arrays_mixed[i], 0, utf8_arrays_mixed[i].length));
        }
    }

    @Setup
    public void prepare() {
        mixed_encode_inputs = new String[count];
        mixed_decode_inputs = new Text[count];
        utf8_arrays_mixed = new byte[count][];
        for (int i = 0; i < count; i++) {
            String s = base.substring(i, i + len);
            s = s.substring(0, len / 2) + "\u4e2d\u56fd" + s.substring(len / 2);
            mixed_decode_inputs[i] = new Text(s);
            utf8_arrays_mixed[i] = mixed_decode_inputs[i].copyBytes();
        }
    }
}
