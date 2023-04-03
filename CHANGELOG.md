# Changelog

## 2.2

- "Crypto Ancienne Meets the Hooded Fang"

- New ports to classic MacOS/MPW and AmigaOS, and contributed ports for SCO Unix 4.2 (SCO ODT) and SerenityOS.

- `carl` now can automatically fallback to TLS 1.2 contexts for sites that don't have ciphers in common with TLS 1.3 (except BeOS, which is always TLS 1.2 currently), along with a `-3` option to prevent fallback for testing and higher security. The `-2` option, conversely, forces TLS 1.2 and is intended for debugging only.

- Use `NO_FUNNY_ALIGNMENT` by default on SPARC, HP PA-RISC, MIPS and SuperH, which avoids crashes and performance-draining trips to the system alignment handler (Alpha on Tru64 still requires `-misalign`).

- Allow wrapped records in TLS 1.3 before changing ciphers.

- Support Fred Fish `egcs` on BeOS/PowerPC.

- Minor local and upstream fixes.

## 2.0

- Support for TLS 1.3 on all supported platforms except classic BeOS
  (which still has support for TLS 1.2).

- ChaCha20Poly1305 now available on all big-endian architectures too.

- New official support for macOS on Apple silicon, with contributed support
  for SCO OpenServer 6 on `i386`, Solaris 9 and 10 on SPARC v9, HP-UX 11.31
  on Itanium, and HP-UX 10.20 and 11.11+ on PA-RISC.

- Multiple crash and early-termination bugs on classic BeOS wallpapered, at
  least with Metrowerks `cc` on PowerPC hardware (see changed build
  instructions).

- Support for RSA-PSS-RSAE-SHA-family signatures.

- Endian detection is now canonicalized and displayed at compile-time.

- Various upstream signature algorithm and verification fixes.

- Minimal `User-Agent` header added to `carl` on the command line to counter
  `HTTP 500` errors from some nginx servers.

- Added a simple TLS hello packet debugger in Perl for development purposes.

## 1.5

- New official support for BeOS R5, Tru64 5.1B, SunOS 4.1 and IRIX 6.5,
  with contributed support for the Mac OS X Public Beta, Cheetah and Puma,
  NeXTSTEP 3.3 on 68K, Professional MachTen 2.3 on 68K, IRIX 6.5 with gcc
  and Haiku R1.

- Fixed test failures on A/UX and Power MachTen.

- Compile-time options for reducing issues with unaligned pointers and
  local variable size.

- Converts all comments to `/* */` for better compiler compatibility.

- Improves RFC 8422 compliance, fixing some server incompatibilities.

- Using secp521r1 due to issues with internal curve25519 implementation
  (to be fixed).

- Adds `-N` option to `carl` and expands exit statuses.

## 1.0

- Initial release on Mac OS X 10.2+, Rhapsody/Mac OS Server, NeXTSTEP 3.3
  on PA-RISC, macOS, Linux, NetBSD, A/UX 3.1, AIX 4+ and Power MachTen 4.1.4.
