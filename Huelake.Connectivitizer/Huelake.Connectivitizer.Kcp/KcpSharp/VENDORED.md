# Vendored: KcpSharp

- Upstream: https://github.com/yigolden/KcpSharp
- Commit: 990a470 ("Update version.json"), package version 0.8.8
- License: MIT (see `LICENSE` in this folder)

## Why vendored

KcpSharp is the C# KCP implementation with the API shape this project needs
(async, stream mode, caller-supplied transport), but it has had no upstream
activity since 2022. Vendoring lets us build it for net10.0 with the trimming
and AOT analyzers on and fix issues ourselves.

## Local changes

- Only the files needed for `KcpConversation` / `KcpStream` are included. The
  `KcpSocketTransport*` helpers and the netstandard shims are left out because
  Connectivitizer owns the UDP socket and demultiplexes datagrams itself.
- The original `KcpSharp` namespace is kept so the code can be diffed against
  upstream.

The wire format must stay compatible with the reference implementation
(https://github.com/skywind3000/kcp); see `docs/protocol` for the fixed
parameters and the interop test.
