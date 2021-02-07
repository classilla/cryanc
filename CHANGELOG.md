# Changelog

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
