package cstc.fiber;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class FiberTest {

    @Test
    public void testFiber() throws Exception {
        int count = 10;
        AtomicInteger ai = new AtomicInteger(0);

        Runnable target = new Runnable() {
            public void run() {
                Thread.yield();
                ai.incrementAndGet();
                System.out.println("after ai: " + ai.get());
            }
        };

        Thread[] vts = new Thread[count];
        ThreadFactory f = Thread.ofVirtual().name("testFiber_", 0).factory();
        for (int i = 0; i < count; i++) {
            vts[i] = f.newThread(target);
        }
        for (int i = 0; i < count; i++) {
            vts[i].start();
        }

        for (int i = 0; i < count; i++) {
            vts[i].join();
        }
        Assertions.assertEquals(ai.get(), count);
    }
}
