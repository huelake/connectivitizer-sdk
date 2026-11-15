# Connectivitizer SDKs

The client libraries of [Connectivitizer](https://connectivitizer.com): reach services on devices behind NAT from your
app, end-to-end encrypted, relayed or peer to peer; or run a device in your own program.

| Folder | Package | Install |
|---|---|---|
| `Huelake.Connectivitizer/` | [Huelake.Connectivitizer.Client](https://www.nuget.org/packages/Huelake.Connectivitizer.Client) (.NET) | `dotnet add package Huelake.Connectivitizer.Client` |
| `connectivitizer-js/` | [@huelake/connectivitizer](https://www.npmjs.com/package/@huelake/connectivitizer) (Node.js, TypeScript) | `npm install @huelake/connectivitizer` |
| `connectivitizer-react-native/` | [@huelake/connectivitizer-react-native](https://www.npmjs.com/package/@huelake/connectivitizer-react-native) | `npm install @huelake/connectivitizer @huelake/connectivitizer-react-native`, then `npx expo install expo-crypto` |
| `connectivitizer-python/` | [huelake-connectivitizer](https://pypi.org/project/huelake-connectivitizer/) (Python) | `pip install huelake-connectivitizer` |
| `connectivitizer-jvm/` | [com.huelake:connectivitizer](https://central.sonatype.com/artifact/com.huelake/connectivitizer) (Kotlin, Java, Android) | `implementation("com.huelake:connectivitizer:<version>")` |

The library for ESP32 (Arduino, PlatformIO, ESP-IDF) is in [huelake/connectivitizer-esp32](https://github.com/huelake/connectivitizer-esp32).

Documentation: [connectivitizer.com/docs](https://connectivitizer.com/docs). Each folder has its own README.

## About this repository

This is a copy of the released sources: every release replaces its content and is tagged with the version. Some tests
need files that are not part of this copy (the protocol test vectors, the interoperability suite). Report problems to
[info@huelake.com](mailto:info@huelake.com), and security issues as described in [SECURITY.md](https://github.com/huelake/.github/blob/main/SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Bundled third-party code keeps its own license, next to it.
