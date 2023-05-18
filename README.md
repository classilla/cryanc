# Crypto Ancienne: TLS for the Internet of Old Things

Copyright (C) 2020-3 Cameron Kaiser and Contributors. All rights reserved.

Crypto Ancienne, or Cryanc for short, is a TLS library with an aim for compatibility with pre-C99 C compilers and geriatric architectures. The [TLS apocalypse](http://tenfourfox.blogspot.com/2018/02/the-tls-apocalypse-reaches-power-macs.html) may have knocked these hulking beasts out of the running for awhile, but now it's time for the Great Old Computing Ones to reclaim the Earth. That old server in your closet? It's only been sleeping, and now it's ready to take back the Web on the Web's own terms. 1997 just called and it's *ticked*.

Cryanc is intended as a *client* library. Although it can facilitate acting as a server, this is probably more efficiently and safely accomplished with a separate reverse proxy to which the encryption can be offloaded.

**The use of this library does not make your application cryptographically secure, and certain systems may entirely lack any technological means to make that possible. Its functionality and security should be regarded as, at best, "good enough to shoot yourself in the foot with."**

## Before you file an issue

- If you are filing an issue for a modern system, you should be using one of the upstream libraries, not this one. If you don't know what the upstreams are, you should read the next section before you do *anything else*.
- If you have not tested your issue against upstream, you should do that first. If it's an upstream bug, don't file it here.
- If you use this for something mission-critical, you are stupid. It may work, but you're still stupid.
- Issues without patches or PRs may or may not be addressed. Ever.

## Supported features

- TLS 1.3 with SNI (on most ports; based on [TLSe](https://github.com/eduardsui/tlse) with local improvements)
- Most standard crypto algorithms (from [`libtomcrypt`](https://github.com/libtom/libtomcrypt))
- Built-in PRNG (`arc4random` from OpenBSD, allegedly, they tell me), with facultative seeding from `/dev/urandom` if present

In addition, `carl`, the included `curl`-like utility and the Cryanc example application, also has:

- SOCKSv4 client support (keep your Old Ones behind a firewall, they tend to cause mental derangement in weaker humans)
- HTTP and HTTPS proxy feature with similarly ancient browsers that do not insist on using `CONNECT` (requires `inetd` or `inetd`-like connecting piece such as [`micro_inetd`](https://acme.com/software/micro_inetd/))
  - Browsers known to work: NCSA X-Mosaic 2.7b\* and [Mosaic-CK](http://www.floodgap.com/retrotech/machten/mosaic/) on Un*xy things, Lynx and [MacLynx](http://www.floodgap.com/retrotech/mac/lynx/) 2.7 and possibly some early versions of 2.8, OmniWeb before 4.2, [Classilla 9.3.4b](http://www.floodgap.com/software/classilla/carl.html), [BeOS NetPositive+](https://oldvcr.blogspot.com/2022/10/going-where-beos-netpositive-hasnt-gone.html) (_not_ regular NetPositive), Magic Cap [Web Browser 3.5.1+](https://oldvcr.blogspot.com/2023/01/bringing-tls-to-magic-cap-datarover.html). Also see [this post](https://oldvcr.blogspot.com/2020/11/fun-with-crypto-ancienne-tls-for.html) and [this post](http://oldvcr.blogspot.com/2022/07/crypto-ancienne-20-now-brings-tls-13-to.html).

See the `carl` manual page in this repo for more (in `man` and Markdown format).

## Not yet supported but coming soon

**Don't file issues about these.** If you do, they will be closed as "user doesn't read documentation" and offenders will be ravenously eaten.

- No 0-RTT or session resumption.
- No ECDSA support. As a result, although certificate validation is available in the library, it is not presently enabled in `carl` as it can't yet validate ECDSA certificates.

These are all acknowledged limitations in TLSe and should improve as upstream does (or our time to work on it).

- Support for other, possibly better (C)PRNGs or the old `prngd`/`egd` protocol.

## Known differences

- kTLS is not presently enabled, even on systems that offer this support (define `WITH_KTLS` if you want it) and even though TLSe supports it: most platforms that need Crypto Ancienne won't have kTLS or a sufficiently new enough implementation and thus this will likely never be the default.

## Working configurations

These are tested using `carl`, which is the included example, and should "just work." Most configurations can build simply with `gcc -O3 -o carl carl.c`. The magic for operating system support is almost all in `cryanc.c`.

- Linux (`gcc`). This is tested on `ppc64le` but pretty much any architecture should be compatible (though see notes below about `NO_FUNNY_ALIGNMENT` if you are using a "classic" RISC CPU).
- NetBSD (`gcc`). Ditto with 32-bit PowerPC, 68K and little-endian MIPS, and probably works on most other BSDs. If someone wants to give this a whack on 4.4BSD or Ultrix I would be highly amused.

- Mach family (OpenSTEP 4.0 probably also works given that these all do):

  - Mac OS X 10.2 through at least 12 (PowerPC, `i386`, `x86_64`, Apple silicon; Xcode `gcc` 3.3+ or `clang`)
  - Mac OS X Server v1.2/Rhapsody 5.6 (PowerPC; `cc` (actually `gcc` 2.7.2.1))
  - Tru64 5.1B (Alpha; `cc` (actually Compaq C V6.5)). Must compile with `-misalign`.
  - NeXTSTEP 3.3 (HP PA-RISC; `cc` (actually `gcc` 2.5))
  - Power MachTen 4.1.4 (PowerPC; `gcc` 2.8.1; `setstackspace 1048576 /usr/bin/cpp` and `setstackspace 4194304 /usr/bin/as`)

- AmigaOS 3.9 (68K; `gcc` 2.95.3 with `ixemul.library` and `ixnet.library`; `-mstackextend` strongly advised). Using library version 63.1; may work on earlier versions and earlier OSes. The [Aminet ADE package](http://aminet.net/package/dev/gcc/ADE) is most convenient for building this. Note that stack usage may be considerable -- my test script uses a stack of 132K minimum.
- IRIX 6.5.30 (SGI MIPS; `cc` (actually MIPSPro 7.4.4m)). For 6.5.22, you may need to use `c99` (older MIPSPro versions may also work with `c99`).
- AIX 4+ (PowerPC, Power ISA; `gcc` 2.7.2.2 and 4.8). This is tested on 4.1.5 and 6.1, and should "just work" on 5L and 7.
- A/UX 3.1 (68K; `gcc` 2.7.2.2, requires `-lbsd` or linking with `/lib/libbsd.a`)
- SunOS 4.1 (SPARC; `gcc` 2.95.2). Binary compatible with Solbourne OS/MP. Tested on OS/MP 4.1C (SunOS 4.1.3).

## Working contributed configurations

These are attested to be working but are maintained by others. Some "just work" and others have specific support in the code base.

- Mac OS X Public Beta through 10.1 (PowerPC; Apple `cc` 912+ (actually `gcc` 2.95.2))
- NeXTSTEP 3.3 (68K; `cc` (actually `gcc` 2.5))
- Professional MachTen 2.3 (68K; `gcc` 2.7.2.f.1)
- IRIX 6.5 (SGI MIPS; `gcc` 9.2.0)
- Haiku R1/beta2 (`x86_64`; `gcc` 8.3.0, requires `-lnetwork`)
- Solaris 9 and 10 (SPARC v9; `gcc` 2.95.3+, requires `-lsocket -lnsl`)
- SCO UNIX 4.2 OpenDesktop (SCO ODT) (`i386`; `gcc` 2.5.8+)
- OpenServer 6 (`i386`; `gcc` 7.3.0, requires `-lsocket`)
- HP-UX 11.31 (Itanium; `cc` A.06.26 and `gcc` 4.7.4)
- HP-UX 11.11+ (HP PA-RISC; `gcc` 4.7.1)
- HP-UX 10.20 (HP PA-RISC; `gcc` 2.95.3, requires `-Doldhpux`)
- SerenityOS (`x86_64`, `gcc` 12+ and `clang` 13+)

## Partially working configurations

These platforms do _not_ "just work." It is possible due to various compiler or OS limitations that they may never work completely.

- BeOS R5 (PowerPC BeBox and Power Macintosh; `cc` (actually Metrowerks CodeWarrior `mwcc` 2.2) or Fred Fish Geek Gadgets `gcc` 2.90.27 (`egcs-1.0.2`)). **This port is very fragile:**
  - Must compile **without optimization** (i.e., `cc -o carl carl.c`, not even `-O`), and you may need to use `carl` with the `-t` option to disable timeouts or long transactions may not complete. For `gcc`, use something like ```
gcc -I`echo $BEINCLUDES | sed 's/;/ -I/g'` -o carl carl.c
```. However, CodeWarrior seems to produce a faster binary than `gcc` even though `gcc` can make a stable binary at `-O3`.
  - TLS 1.3 is _not_ currently supported due to limited system resources; all requests are TLS 1.2.
  - Due to differences in the way BeOS treats standard input, reading proxy requests from the TTY doesn't currently work (it does from files).
  - Should work with `x86`; not tested with Dano, ZETA or BONE. These versions may not require these limitations. Submit your patch, you can help! (If you're using Haiku, you can just compile Cryanc normally.)

- Classic MacOS (PowerPC; MPW `MrC` 4.1.0f1c1 or better). This generates an MPW tool version of `carl` that runs within the MPW Shell or ToolServer. MacOS being MacOS, it has its own weir-dass build instructions:
  - Install MPW and the [GUSI library distribution](https://sourceforge.net/projects/gusi/files/) if you haven't already, making sure you run the installation scripts or your setup won't have all the necessary headers. We use GUSI's latest version 2.2.3 but earlier versions may work. You also need to ensure that `${GUSI}` is set to your installation folder, which the installation should do for you (e.g., `Set -e "Macintosh HD:GUSI_223:"`).
  - UnStuff `carl_mpw.sit.hqx`; you should get a folder named `mpw`. Open the `Makefile` inside it (it should start the MPW Shell) and ensure your working directory is that `mpw` folder, not the `cryanc` folder it's within.
  - Press Command-B to build, and enter the target `carl`. The `Makefile` will fix up the type and creator of the source files and generate a tool `carl` in the same `mpw` folder.
  - To run `carl` from the MPW Shell, just enter `carl` or `carl -options "URL"` (the URL must be quoted since slashes can be salient to MPW). `carl` will cooperatively multitask with MPW and other applications while running, even if a host does not respond (press Command-. to cancel a request). However, due to differences in the way the Shell treats standard input, reading proxy requests directly from the keyboard doesn't currently work (it does from files and pipes).
  - **`MrC` generates verifiably incorrect code.** To reduce this risk, we disable optimization and spot-enable it only for certain critical or likely-safe functions. It is possible it has other bugs that cause miscompiles or crashes, or those functions aren't actually as safe as we think they are. Because most of the code is not optimized, you may need to use `carl` with the `-t` option to disable timeouts or long transactions may not complete.
  - Because of high stack demands, if you experience crashes you may need to expand the MPW Shell's default stack allotment for tools. The `HEXA` 128 resource contains the default stack space as a 32-bit integer; a value of `0008 0000` would be 512K, for example.
  - To use the `carl` MPW tool as a proxy requires a Mac `inetd` clone. The GUSI docs talk about "David Petersons `inetd`" [sic] but we can't find this (can you help?). We are exploring whether [ToolDaemon](https://github.com/fblondiau/ToolDaemon) can be hacked to serve this purpose, since the source code is available. In the meantime, if you need to run it as a proxy for Classilla or MacLynx, your best bet right now is to compile and run `carl` under Power MachTen -- and it will probably be more stable, too.

## Not tested or not working but might in the future

- Classic Mac OS (68K `SC` with GUSI; or PowerPC MPW `gcc` 2.5 with GUSI; or Metrowerks CodeWarrior on 68K or PowerPC with GUSI and SIOUX). The `gcc` MPW requires that the source files be converted to CR instead of CRLF and has other odd quirks, but should avoid `MrC`'s code generation problems. The same may apply for CodeWarrior. As for 68K Macs, the existing code may already work with Symantec C under MPW but I haven't tried, and unfortunately most 68K Macs will not be fast enough for many sites (see notes below about systems slower than 40MHz).
- It should be possible to port to Win32 with something like `mxe`; there are hooks for it in TLSe already.
- Solaris 2+ should work now that SunOS 4 does.
- HP-UX on 68K. We have one locally.
- Would be nice to eliminate the `ixemul` and `ixnet` dependencies for AmigaOS, but it was the easiest way of getting the port launched. Would also consider `libnix`-based code.
- The people demand a VMS port! Need to check the license for that C compiler on our VAXstation ...

## Porting it to your favourite geriatric platform

Most other platforms with `gcc` 2.5 or higher, support for 64-bit ints (usually `long long`) and `stdarg.h` should "just work."

If your system lacks `stdint.h`, you can try using `-DNOT_POSIX=1` to use the built-in definitions. You may also need to add `-include stdarg.h` and other headers. Consider compiling with `-DDEBUG` if you get crashes so you can see where it dies (it's also a neat way to see TLS under the hood).

A few architectures, especially old RISC, may not like the liberties taken with unaligned pointers and memory access. For these systems try `-DNO_FUNNY_ALIGNMENT`, which is the default for SPARC, HP PA-RISC, MIPS and SuperH. However, it seems we may not have smoked all of them out (for example, it's not good enough for DEC Alpha on Tru64, the king of alignment-finicky configurations, and we still have to use `-misalign` with the Compaq C compiler).

Large local stack allocations are occasionally used for buffering efficiency. If your compiler doesn't like this (Metrowerks comes to mind) or you get crashes when `carl` terminates, try `-DBIG_STRING_SIZE=xx`, substituting a smaller buffer size like 16384 or 4096.

Once you figure out the secret sauce, we encourage you to put some additional blocks into `cryanc.c` to get the right header files and compiler flags loaded. PRs accepted for these as long as no presently working configuration is regressed. Similarly, we would love to further expand our compiler support, though we now support quite a few.

Some systems may be too slow for present-day server expectations and thus will appear not to function even if the library otherwise works correctly. In our testing this starts to become a problem for CPUs slower than 40MHz or so, regardless of architecture. Even built with `-O3`, our little NetBSD Macintosh IIci with a 25MHz 68030 and no L2 card took 22 seconds
(give `carl` the `-t` option to disable timeouts) for a single short TLS 1.2 transaction to a local test server; a number of Internet hosts we tested it with simply cut the connection instead of waiting. Rude!

## Using it in your application

A simple `#include "cryanc.c"` is sufficient (add both `cryanc.c` and `cryanc.h` to your source code). `cryanc.h` serves to document the more or less public interface and can be used if you turn Cryanc into a library instead of simply merging it into your source.

`carl` demonstrates the basic notion:

- open a TCP socket
- `tls_create_context` creates the TLS context (`TLS_V12` or `TLS_V13`)
- `tls_sni_set` sets the SNI hostname for the context
- `tls_client_connect` initializes the connection

Your application then needs to service reads and writes. The loop at the end of `carl` is a complete example, using `select(3)` to determine when data has arrived, and using an additional interior read loop to satisfy some servers that demand the socket be serviced promptly.

As data accumulates from the TLS hello and calls to `tls_write`,
it should check `tls_get_write_buffer` and send this data down the socket. `carl` has a helper function called `https_send_pending` which it calls periodically to do this. Once the context write buffer is serviced, it clears the context buffer with `tls_buffer_clear`.

Likewise, as data is read from the socket, it is sent to `tls_consume_stream`. When the secure connection is established, `tls_established` will become true for the context and you can read data from `tls_read`.

If a TLS alert occurs, it can be fetched from `context->error_code`.

## Language pedantry note

Here, "crypto" is short for *la cryptographie* and therefore the use of the feminine singular *ancienne*, so there.

## Licenses and copyrights

Crypto Ancienne is released under the BSD license.

Copyright (C) 2020-3 Cameron Kaiser and Contributors. All rights reserved.

Based on TLSe. Copyright (C) 2016-2023 Eduard Suica. All rights reserved.

Based on Adam Langley's implementation of Curve25519. Copyright (C) 2008 Google, Inc. All rights reserved.

Based on OpenBSD's `arc4random` (allegedly). Copyright (C) 1996 David Mazieres. All rights reserved.

Based on `libtomcrypt` by Tom St Denis and contributors. Unlicense.

Based on public domain works by D. J. Bernstein.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
