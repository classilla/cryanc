# Crypto Ancienne: TLS for the Internet of Old Things

Copyright (C) 2020 Cameron Kaiser. All rights reserved.

Crypto Ancienne, or Cryanc for short, is a TLS library
with an aim for compatibility with pre-C99 C compilers and
geriatric architectures. The [TLS apocalypse](http://tenfourfox.blogspot.com/2018/02/the-tls-apocalypse-reaches-power-macs.html) may have knocked these hulking beasts out
of the running for awhile, but now it's time for the Great Old Computing Ones
to reclaim the Earth. That old server in your closet? It's only been sleeping,
and now it's ready to take back the Web on the Web's own terms. 1997 just called and
it's *ticked*.

Cryanc is intended as a *client* library. Although it can facilitate acting as a server,
this is probably more efficiently and safely accomplished with a separate reverse proxy
to which the encryption can be offloaded.

**The use of this library does not make your application cryptographically
secure, and certain systems may entirely lack any technological means to
make that possible. Its functionality and security should be regarded as,
at best, "good enough to shoot yourself in the foot with."**

## Before you file an issue

- If you are filing an issue for a modern system, you should be using one of the upstream libraries, not this one. If you don't know what the upstreams are, you should read the next section before you do *anything else*.
- If you have not tested your issue against upstream, you should do that first. If it's an upstream bug, don't file it here.
- If you use this for something mission-critical, you are stupid. It may work, but you're still stupid.
- Issues without patches or PRs may or may not be addressed. Ever.

## Supported features

- TLS 1.2 with SNI (based on [TLSe](https://github.com/eduardsui/tlse) with local improvements)
- Most standard crypto algorithms (from [`libtomcrypt`](https://github.com/libtom/libtomcrypt))
- Built-in PRNG (`arc4random` from OpenBSD, allegedly, they tell me), with facultative seeding from `/dev/urandom` if present

In addition, `carl`, the included `curl`-like utility and the Cryanc example application, also has:

- SOCKSv4 client support (keep your Old Ones behind a firewall, they tend to cause mental derangement in weaker humans)
- HTTP and HTTPS proxy feature with similarly ancient browsers that do not insist on using `CONNECT` (requires `inetd` or `inetd`-like connecting piece such as [`micro_inetd`](https://acme.com/software/micro_inetd/))

## Not yet supported but coming soon

**Don't file issues about these.** If you do, they will be closed as "user doesn't read
documentation" and offenders will be ravenously eaten.

- TLS 1.3. Many sites work but some abort during transmission like Github.
- No 0-RTT or session resumption.
- No ECDSA support. As a result, although certificate validation is available in the library, it is not presently enabled in `carl` as it can't yet validate ECDSA certificates.
- ChaCha20 not yet supported on big-endian.

These are all acknowledged limitations in TLSe and should improve as upstream does.

- Support for other, possibly better (C)PRNGs or the old `prngd`/`egd` protocol.

## Working configurations

These are tested using `carl`, which is the included example. Most configurations can build simply with `gcc -O3 -o carl carl.c`. The magic for operating system support is almost all in `cryanc.c`.

- Linux (`gcc`). This is tested on `ppc64le` but pretty much any architecture should work.
- NetBSD (`gcc`). Ditto, and probably works on most other BSDs. If someone wants to give this a whack on 4.4BSD I would be highly amused.

Mach family:

- Mac OS X 10.2 through at least 10.14 (PowerPC, `i386`, `x86_64`; Xcode `gcc` 3.3+ or `clang`)
- Mac OS X Server v1.2/Rhapsody 5.6 (PowerPC; `cc` (actually `gcc` 2.7.2.1))
- NeXTSTEP 3.3 (HP PA-RISC; `cc` (actually `gcc` 2.5))

OpenSTEP 4.0 probably also works given that these all do.

- AIX 4+ (PowerPC, Power ISA; `gcc` 2.7.2.2 and 4.8). This is tested on 4.1.5 and 6.1, and should "just work" on 5L and 7.

- A/UX 3.1 (68K; `gcc` 2.7.2.2, requires `-lbsd`)

- Power MachTen 4.1.4 (PowerPC; `gcc` 2.8.1; `setstackspace 1048576 /usr/bin/cpp` and `setstackspace 4194304 /usr/bin/as`)

## Partially working configurations

- IRIX (SGI MIPS; MIPSPro 7.4 `c99` and `gcc` 9). Builds and unencrypted HTTP works but TLS segfaults due to issues with some codeblocks that cast byte arrays to `unsigned short`s using `htons()` and other such functions. This should be correctable, just tedious.

## Doesn't compile but planned

- SunOS 4 (`gcc` 2.7). This requires changes to `libtomcrypt` to support older `varargs.h` variadic function prototypes but will likely get other very old systems working as well. Binary-compatible with Solbourne OS/MP.
- Classic Mac OS (PowerPC with GUSI and MPW `gcc` 2.5). For full function this port would also need an `inetd`-like tool such as [ToolDaemon](https://github.com/fblondiau/ToolDaemon). For now, your best bet is to use Power MachTen.
- Tru64. I've got a 164LX sitting here doing nothing ...

## Porting it to your favourite geriatric platform

Most other platforms with `gcc` 2.5 or higher and support for 64-bit ints
(usually `long long`) and `stdarg.h` should "just work."

If your system lacks `stdint.h`, you can try using `-DNOT_POSIX=1` to use the built-in
definitions. You may also need to add `-include stdarg.h` and other headers.

Once you figure out the secret sauce, we encourage you to put some additional blocks
into `cryanc.c` to get the right header files and compiler flags loaded. PRs accepted for 
these as long as no presently working configuration is regressed. Similarly, we would
love this to work on other compilers (right now it is terribly `gcc`-centric).

Some systems may be too slow for present-day server expectations and thus will appear
not to function even if the library otherwise works correctly. Even built with `-O3`, our little NetBSD
Macintosh IIci with a 25MHz 68030 and no L1 card took 22 seconds
(give `carl` the `-t` option to
disable timeouts) for a single short TLS 1.2
transaction to a local test server; a number of Internet hosts we tested it with simply cut the
connection instead of waiting. Rude!

## Using it in your application

A simple `#include "cryanc.c"` is sufficient (add both `cryanc.c` and `cryanc.h` to your
source code). `cryanc.h` serves to document the more or less public interface and
can be used if you turn Cryanc into a library instead of simply merging it into your source.

`carl` demonstrates the basic notion:

- open a TCP socket
- `tls_create_context` creates the TLS context (`TLS_V12` or `TLS_V13`)
- `tls_sni_set` sets the SNI hostname for the context
- `tls_client_connect` initializes the connection

Your application then needs to service reads and writes. The loop at the end of
`carl` is a complete example, using `select(3)` to determine when data has
arrived.

As data accumulates from the TLS hello and calls to `tls_write`,
it should check `tls_get_write_buffer` and send this data down the socket. `carl`
has a helper function called `https_send_pending` which it calls periodically to
do this. Once the context write buffer is serviced, it
clears the context buffer with `tls_buffer_clear`.

Likewise, as data is read from the socket, it is sent to `tls_consume_stream`. When
the secure connection is established, `tls_established` will become true for the
context and you can read data from `tls_read`.

If a TLS alert occurs, it can be fetched from `context->error_code`.

## Language pedantry note

Here, "crypto" is short for *la cryptographie* and therefore the use of the feminine
singular *ancienne*, so there.

## Licenses and copyrights

Crypto Ancienne is released under the BSD license.

Copyright (C) 2020 Cameron Kaiser. All rights reserved.

Based on TLSe. Copyright (C) 2016-2020 Eduard Suica. All rights reserved.

Based on Adam Langley's implementation of Curve25519. Copyright (C) 2008 Google, Inc. All rights reserved.

Based on OpenBSD's `arc4random` (allegedly). Copyright (C) 1996 David Mazieres. All rights reserved.

Based on `libtomcrypt` by Tom St Denis and contributors.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or other
materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
