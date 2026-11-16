# Connectivitizer SDK for the JVM (Java, Kotlin, Android)

`com.huelake:connectivitizer`: reach a service on a device behind NAT from Java, Kotlin or an Android app, and run a device on the JVM. Sessions are encrypted end to end with a key only the device and the application hold; they run peer to peer when the networks allow it and through the Connectivitizer relay when they do not.

It speaks the same protocol as the .NET library, `cz`, the TypeScript and Python SDKs and the ESP32 library.

```kotlin
ConnectivitizerClient.builder(apiUrl).apiKey("czk_…").sharedKey("czs_…").build().use { client ->
    val session = client.connect("living-room-lamp", listOf("api"))
    println(session.fetch("api", "/state").text())
    println(session.info.mode)   // "direct" or "e2e-relay"
}
```

From Java: `connectBlocking` / `connectAsync` (a `CompletableFuture`), `session.fetchBlocking`, `agent.runBlocking()`. The guide with Java and Kotlin examples: [https://connectivitizer.com/guides/jvm.md](https://connectivitizer.com/guides/jvm.md).

## Install

From Maven Central; the latest version is shown on [central.sonatype.com](https://central.sonatype.com/artifact/com.huelake/connectivitizer).

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.huelake:connectivitizer:<version>")
}
```

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.huelake</groupId>
    <artifactId>connectivitizer</artifactId>
    <version><!-- version --></version>
</dependency>
```

Java 11 bytecode; Android 9 (API 28) or newer. The only dependency is `kotlinx-coroutines-core`. Building needs a JDK from 17 to 24 for Gradle (the toolchain is 17).

## Design

- **One thread for the protocol.** Each client and agent has a single-threaded dispatcher; all protocol state (sessions, multiplexer, KCP) lives there, so it needs no locks. Socket reads run on the IO pool and hand their data over. Public methods switch to that thread, so they can be called from anywhere.
- **No platform gaps on Android.** X25519 is implemented in the library (Android's JCA has none before API 33); ChaCha20-Poly1305, HMAC-SHA256 and ECDSA P-256 come from the JCA, which has them from Android 9. JSON, WebSocket, HTTP/1.1, KCP and STUN are in the library.
- **Direct sessions need nothing from the application.** `Platform` binds a dual-stack `DatagramChannel` on a port the system picks and reads the machine's addresses from `NetworkInterface` (VPN interfaces skipped).
- TLS connections to the platform check the certificate's host name (`endpointIdentificationAlgorithm = HTTPS`), which Java does not do by default for plain sockets.

## Checks

```
./gradlew test                  # the channel, multiplexing, KCP over a lossy link
```

Each release is also tested against the control plane and the relay with the .NET library, the TypeScript SDK and the Python SDK on the other side, relayed and peer to peer. These tests run on the JVM, not on an Android device.

## Limits

- The shared key is the only end-to-end layer. Certificates with pairing, and enrollment with a one-time token, are in `cz`, the .NET library and the TypeScript SDK on Node.js.
- Direct sessions use UDP. Direct connections over TCP are in `cz` and the .NET library only.
- A device run by this library cannot be reached in compatibility mode (through the gateway).
