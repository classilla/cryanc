# carl(1) - Crypto Ancienne Resource Loader

Crypto Ancienne

```
carl [options] url
```


<a name="description"></a>

# Description

**carl**
is both a demonstration application for the Crypto Ancienne TLS library and a utility reminiscent of the much more comprehensive
**curl**(1),
of which its name is a desperate pun. It may also be more suitable as a
**curl**(1)
substitute for the older systems that Crypto Ancienne caters to, since
it has no prerequisites other than a compatible C compiler.

Like its inspiration,
**carl**
fetches URLs, emitting them to standard output. However,
**carl**
only supports HTTP and HTTPS (and only HTTP/0.9, HTTP/1.0 and HTTP/1.1), although it will also parse SOCKS URLs and use them as proxies (see
**ENVIRONMENT**).

**carl**
can also accept complete
HTTP and HTTPS requests over standard input (see
**PROXY**
**MODE**).
If connected to
**inetd**(8)
or a similar utility, this can act as a complete proxy solution, including for some browsers which may not speak HTTPS or
current TLS versions themselves but can be trained or tricked to send requests for
**https://**
URLs to it.


<a name="options"></a>

# Options

In general, options do not match
**curl**(1)'s.


* **-q**  
  Quiet mode; no verbose errors are displayed (see
  **EXIT**
  **STATUS**).
* **-t**  
  Disable timeouts. Otherwise, transactions that take longer than 10 seconds are aborted. Necessary for slower systems that may not negotiate TLS quickly enough. Given that Crypto Ancienne specifically caters to such systems, this option may become the default in future versions.
* **-H**  
  Use
  **HEAD**
  as the request method instead of
  **GET**.
  In this mode, HTTP(S) headers are displayed automatically, along with any residual message body that may be transmitted by some servers. Other methods such as
  **POST**
  must be specified as proxy requests (i.e., sent over standard input when
  **-p**
  is specified).
* **-i**  
  Dump both headers and body, even if
  **-H**
  isn't specified. Irrelevant in proxy mode (when
  **-p**
  is specified).
* **-N**  
  Ignore the
  **ALL_PROXY**
  environment variable, if it exists (see
  **ENVIRONMENT**).
* **-u**  
  Treat all HTTP URLs as HTTPS, even if they are specified as HTTP. This includes URLs received in proxy mode (when
  **-p**
  is specified).
* **-s**  
  Downgrade HTTP/1.1 replies to HTTP/1.0 for consumers or clients which are intolerant. Irrelevant if headers are not displayed (i.e., without
  **-H**,
  **-p**
  or
  **-i**).
* **-2**  
  Maximally negotiate TLS 1.2 instead of TLS 1.3. This is primarily for analysing handshake failures; under typical circumstances requiring this option to access a site should be considered a bug.
* **-3**  
  Conversely, do not allow fallbacks to a TLS 1.2 context if negotiating a TLS 1.3 context fails. By default
  **carl**
  will retry such connections to account for those hosts that genuinely support TLS 1.2 but not any of the ciphers that TLS 1.2 and TLS 1.3 would have in common. These sites are getting fewer and fewer, and thus this option may become the default in future versions.
* **-p**  
  Enables proxy mode (see
  **PROXY**
  **MODE**).
  **-i**,
  **-q**,
  and
  **-H**,
  if they are specified, are ignored. If a URL is provided, it may only be a
  **socks://**
  or
  **socks5://**
  URL, which is used as a SOCKS proxy for
  **carl**
  to relay through (see the
  **ALL_PROXY**
  environment variable in
  **ENVIRONMENT**).
* **-v**  
  Display version string (the same as the main library).
* **-h**  
  Display a synopsis of these options.
  

<a name="proxy-mode"></a>

# Proxy Mode

If the
**-p**
option is specified,
**carl**
will accept a full proxy client request for an
**http://**
or
**https://**
URL from standard input. It must be formatted as a standard HTTP proxy request with method
and fully-specified URL minimally compliant to RFC 7230, though
**carl**
is tolerant, and will quietly adjust client requests as needed or requested (see also the
**-u**
and
**-s**
options). A full HTTP reply with all remote headers will be sent in response.

The request must be delimited by the standard two-CRLF separator. If the method is intended to send data to the server, such as
**POST**,
the payload may trail the request headers after it.
**carl**
does no encoding of this data; your application must do that itself.

In proxy mode, the _url_ argument may only be used to specify a SOCKS proxy through which the request will be forwarded. If the
**ALL_PROXY**
environment variable exists, specifying a SOCKS URL on the command line will override it (or use
**-N**
to ignore it; see
**ENVIRONMENT**).
Otherwise,
**carl**
will connect directly.

The
**CONNECT**
method is intentionally not implemented.

**carl**
does not bind any server port itself. However, because this mode accepts data on standard input, any
**inetd**(8)
or
**inetd**(8)-like
superserver environment such as
**xinetd**(8)
or
**micro_inetd**(1)
can be used to make it accessible on the network. _Careful: if you bind an external interface, you've just made your computer into an open HTTP proxy!_
**carl**
implements no access controls or authentication, so check your superserver's documentation on how to only bind an internal interface or the loopback.

<a name="environment"></a>

# Environment


* **ALL_PROXY**  
  **carl**
  has built-in SOCKSv4 client support. If a SOCKS URL (either
  **socks://**
  or
  **socks5://**,
  which is treated as a synonym) is specified in this environment variable, all requests will be forwarded through it.
  If a port number is not specified in the URL, it is assumed to be 1080. Any provided path or arguments are ignored.
  **carl**
  does not support authentication or SOCKSv5 features, and requires your DNS be able to resolve hostnames.
* This variable is ignored if
  **-N**
  is specified on the command line, and it is overridden in proxy mode
  (**-p**)
  if a SOCKS URL is specified on the command line.

**NO_PROXY**
is not currently implemented.

<a name="exit-status"></a>

# Exit Status

A possibly helpful message may also appear unless it is suppressed by
**-q**.
These exit return codes may be expanded in future versions.

* **0**
  No error.
* **1**
  The request is pathological (nonsense, inappropriate or incomplete). This can also occur when a non-SOCKS proxy is provided
  (**carl**
  does not talk to other HTTP proxies; they are vapid and uninteresting at parties).
* **2**
  The host or proxy host could not be resolved.
* **3**
  The host resolved to an IPv6 address, but
  **carl**
  doesn't support those yet.
* **4**
  The connection to the SOCKS proxy failed.
* **5**
  The connection to the HTTP(S) server failed.
* **6**
  The TLS response from the HTTPS server could not be processed.
* **253**
  No data was received.
* **254**
  Timeout. Consider using
  **-t**
  if the system is slower and the request should have worked.
* **255**
  General failure.
  

<a name="notes"></a>

# Notes

**carl**
does not currently evaluate certificates for validity, so its encryption support is best considered opportunistic and it
should not be used for high-security environments.


<a name="see-also"></a>

# See Also

**curl**(1)


<a name="home-page"></a>

# Home Page

https://github.com/classilla/cryanc


<a name="author"></a>

# Author

(C)2020-3 Cameron Kaiser and Contributors. All rights reserved. Additional copyrights apply; see the home page for full credits. BSD license.
