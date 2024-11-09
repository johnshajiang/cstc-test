/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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
 */

package cstc.crypto;

import cstc.util.Util;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.TimeUnit;

import static cstc.util.Util.toBytes;

@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class AESCTRPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("10000000000000000000000000000001");

    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "AES");
    private static final IvParameterSpec IV_PARAM_SPEC = new IvParameterSpec(IV);

    private final static byte[] DATA = Util.dataMB(1);

    @State(Scope.Benchmark)
    public static class EncrypterHolder {

        Cipher encrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            encrypter = Cipher.getInstance("AES/CTR/NoPadding");
            encrypter.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolder {

        Cipher decrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            decrypter = Cipher.getInstance("AES/CTR/NoPadding");
            decrypter.init(Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
        }
    }

    @Benchmark
    public byte[] encrypt(EncrypterHolder holder) throws Exception {
        return holder.encrypter.doFinal(DATA);
    }

    @Benchmark
    public byte[] decrypt(DecrypterHolder holder) throws Exception {
        return holder.decrypter.doFinal(DATA);
    }
}
