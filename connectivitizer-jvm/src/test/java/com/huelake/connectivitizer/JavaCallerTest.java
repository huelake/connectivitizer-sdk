package com.huelake.connectivitizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

/**
 * The SDK as a Java program calls it. Written in Java on purpose: that this file compiles is half the test
 * (a Java caller can catch ConnectivitizerException by its type).
 */
class JavaCallerTest {
    @Test
    void javaCatchesTheSdksErrorByItsType() {
        try {
            ConnectivitizerClient.builder("http://127.0.0.1:9").apiKey("czk_x").sharedKey("not a key").build().close();
            fail("an invalid shared key is refused");
        } catch (ConnectivitizerException e) {
            assertEquals(ErrorCodes.INVALID_REQUEST, e.getCode());
        }
    }

    @Test
    void theBlockingCallsNeedNoThrowsClause() {
        // No "throws Exception" on this method: the blocking API declares nothing, and its error is unchecked.
        try (ConnectivitizerClient client = ConnectivitizerClient.builder("http://127.0.0.1:9").apiKey("czk_x").build()) {
            client.connectBlocking("nowhere", java.util.List.of("api"));
            fail("nothing listens on port 9");
        } catch (ConnectivitizerException e) {
            assertEquals(false, e.getCode().isEmpty());
        }
    }

    @Test
    void aDeviceOffersJavaTheCallsThatOpenSessions() throws InterruptedException {
        ConnectivitizerAgent agent = ConnectivitizerAgent.builder("http://127.0.0.1:9").deviceKey("czd_x").name("here")
                .sharedKey(SharedKey.generate()).build();
        assertEquals(0, agent.getOutgoingSessions().size());
        agent.stopBlocking();
        try {
            agent.connectBlocking("there", java.util.List.of("api"));
            fail("a stopped device opens no session");
        } catch (ConnectivitizerException e) {
            assertEquals(ErrorCodes.SESSION_CLOSED, e.getCode());
        }
        try {
            agent.listDevicesBlocking();
            fail("a stopped device asks nothing");
        } catch (ConnectivitizerException e) {
            assertEquals(ErrorCodes.SESSION_CLOSED, e.getCode());
        }
        try {
            agent.connectAsync("there", java.util.List.of("api")).get();
            fail("a stopped device opens no session");
        } catch (java.util.concurrent.ExecutionException e) {
            assertEquals(ErrorCodes.SESSION_CLOSED, ((ConnectivitizerException) e.getCause()).getCode());
        }
    }
}
