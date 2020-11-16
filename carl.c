/*
 * Crypto Ancienne Resource Loader "carl" (and example application)
 * Copyright 2020 Cameron Kaiser. All rights reserved.
 * BSD license (see README.md)
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#if !defined(__AUX__) && (!defined(NS_TARGET_MAJOR) || (NS_TARGET_MAJOR > 3))
#include <sys/select.h>
#endif
#include <netinet/in.h>
#include <netdb.h> 

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

/* stdint or equivalent set here */
#include "cryanc.c"

int quiet = 0;
int proxy = 0;
int http09 = 0;

void error(char *msg) {
    if (proxy) {
        if (!http09)
            fprintf(stdout, "HTTP/1.0 502 Proxy Error\r\n"
                            "Content-type: text/html\r\n\r\n");
        fprintf(stdout, "%s\n", msg);
        exit(255);
    }

    if (!quiet) {
        if (errno > 0) perror(msg); else fprintf(stdout, "%s\n", msg);
    }
    exit(255);
}

void timeout() { /* portable enough */
    if (quiet) exit(254);
    error("Timeout");
}

int https_send_pending(int client_sock, struct TLSContext *context) {
    unsigned int out_buffer_len = 0;
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

/* NYI */
int validate_certificate(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len) {
    int i;
    if (certificate_chain) {
        for (i = 0; i < len; i++) {
            struct TLSCertificate *certificate = certificate_chain[i];
            // check certificate ...
        }
    }
    //return certificate_expired;
    //return certificate_revoked;
    //return certificate_unknown;
    return no_error;
}

int scheme_is(char *url, char *scheme) {
    if (strlen(url) <= strlen(scheme)) return 0;
    return (strstr(url, scheme) == url);
}

/* given a URL string, set hostname, port and protocol (identified by well
   known service port number) and return where in the string the path
   starts (or NULL if it didn't parse correctly). */
char *parse_url(char *url, char *hostname, size_t *port, size_t *proto) {
    char *h, *p, *pn;
    unsigned int i;

    if (scheme_is(url, "socks://")) {
        *proto = 1080;
    } else if (scheme_is(url, "socks5://")) {
        *proto = 1080;
    } else if (scheme_is(url, "http://")) {
        *proto = 80;
    } else if (scheme_is(url, "https://")) {
        *proto = 443;
    } else
        return NULL; /* we don't know this protocol */

    /* find the second slash: that's where the hostname starts. */
    for (h=url,i=0;*h && i!=2;h++) if(*h=='/') i++;
    if (i != 2) return NULL; /* ran off the end of the string */

    /* find the third slash: that's where the selector starts. */
    for (p=h;*p && i!=3;p++) if(*p=='/') i++;
    /* if there is no third slash, treat as a zero-length path */
    if (i == 3) p--;

    /* hostname:port must be at least 1 character long. */
    if ((p - h) < 1) return NULL;

    if ((pn = strchr(h, ':')) && pn < p) {
        /* automatic null termination */
        char sport[6] = { 0, 0, 0, 0, 0, 0 };

        /* check hostname and port lengths */
        if (pn == h || (pn - h) > 255 || (p - pn) < 2 || (p - pn) > 6)
            return NULL;

        memcpy((void *)hostname, (void *)h, (pn - h));
        *(hostname + (pn - h)) = '\0';
        memcpy((void *)&sport, (void *)++pn,  (p - pn));

        *port = atoi(sport);
        if (*port < 1 || *port > 65535) return NULL;

        /* atoi will allow something like :3aa but we shouldn't */
        if (*port < 10    && (p - pn) != 1) return NULL;
        if (*port > 9     && *port < 100   && (p - pn) != 2) return NULL;
        if (*port > 99    && *port < 1000  && (p - pn) != 3) return NULL;
        if (*port > 999   && *port < 10000 && (p - pn) != 4) return NULL;
    } else {
        if ((p - h) > 255) return NULL;

        memcpy((void *)hostname, (void *)h, (p - h));
        *(hostname + (p - h)) = '\0';
        *port = *proto;
    }

    /* we don't support authority information currently */
    if (strchr(hostname, '@')) return NULL;

    return p;
}

void help(int longdesc, char *me) {
    fprintf(stderr, "Crypto Ancienne Resource Loader v1.0\n");
    if (!longdesc) return;

    fprintf(stderr,
"Copyright (C)2020 Cameron Kaiser. All rights reserved.\n"
"usage: %s [option] [url (optional if -p)]\n\n"
"protocols: http https\n\n"
"-h This message\n"
"-v Version string\n"
"-p Proxy mode (accepts HTTP client request on stdin, ignores -i -q -H)\n"
"   If url is also specified, it may be a socks:// URL only\n"
"-H HEAD request (default is GET)\n"
"-q Emit no errors, only status code\n"
"-i Dump both headers and body (default is body only, irrelevant if -H or -p)\n"
"-t No timeout (default is 10s)\n"
"-u Upgrade HTTP requests to HTTPS transparently\n"
"-s Spoof HTTP/1.1 replies as HTTP/1.0 (irrelevant without -H, -p or -i)\n"
    , me);
}

int main(int argc, char *argv[]) {
    int sockfd, n, proxycon = 0, forever = 0, spoof10 = 0;
    size_t portno, socksport, proto, socksproto, numcrs = 0, bytesread = 0;
    struct sockaddr_in serv_addr;
    struct hostent *server, *socksserver;
    fd_set fdset;
    char hostname[256], sockshost[256], *buffer;
    unsigned char read_buffer[0xffff];
    unsigned char client_message[8192];
    int read_size;
    int sent = 0, arg = 0, head_only = 0, with_headers = 0, upgrayedd = 0;
    char *path = NULL, *url = NULL, *proxyurl = NULL;
    struct TLSContext *context;

    proxyurl = getenv("ALL_PROXY");

    for(;;) {
        if (++arg >= argc) {
           if (proxy) break;

           help(1, argv[0]);
           return 1;
        }
        if (argv[arg][0] != '-') {
           url = argv[arg];
           break;
        }

        if (strchr(argv[arg], 'v')) { help(0, argv[0]); return 0; }
        if (strchr(argv[arg], 'h')) { help(1, argv[0]); return 0; }
        if (strchr(argv[arg], 'i')) { with_headers = 1; }
        if (strchr(argv[arg], 'H')) { head_only = 1; with_headers = 1; }
        if (strchr(argv[arg], 'u')) { upgrayedd = 1; }
        if (strchr(argv[arg], 's')) { spoof10 = 1; }
        if (strchr(argv[arg], 't')) { forever = 1; }
        if (strchr(argv[arg], 'q')) { quiet = 1; }
        if (strchr(argv[arg], 'p')) { proxy = 1; }
    }

    if (proxy) {
        /* receiving a proxy request from stdin */

        char method[10], purl[2048];
        size_t read = 0;
        int c, mc = 0, mu = 0, got_method = 0, got_url = 0;

        if (url) proxyurl = url;

        head_only = 0; quiet = 1; with_headers = 0; http09 = 1;
        method[0] = '\0'; purl[0] = '\0';
        for(;;) {
            c = fgetc(stdin);
            if (c == EOF) return 1; /* something's wrong */

            if (c == ' ') {
                if (!got_method) { got_method = 1; continue; }
                if (!got_url) { got_url = 1; http09 = 0; break; }
                return 1; /* something's wrong here too */
            }
                     
            if (c == '\r') {
                if (!got_method) return 1;
                if (got_url) return 1; /* ?! */
                got_url = 1; continue;
            }

            if (c == '\n') {
                if (got_method) break;
                return 1; /* something's wrong here too */
            }

            if (!got_method) {
                method[mc++] = (char)c; method[mc] = '\0';
                if (mc == 9) return 1; /* bogus method */
                continue;
            }

            if (!got_url) {
                purl[mu++] = (char)c; purl[mu] = '\0';
                if (mu == 2047) return 1; /* too long */
                continue;
            }

            fprintf(stderr, "unhandled character: %c\n", (char)c);
            exit(255);
        }
        
        /* at this point, we either have a complete 0.9 request, or a 1.0/1.1
           request with more bytes to follow. */

        if (!strlen(method) || !strlen(purl)) exit(1);

        if (http09 && strcmp(method, "GET")) {
            fprintf(stdout, "Only GET is supported for HTTP/0.9\n");
            return 1;
        }
        if (!strcmp(method, "CONNECT")) {
            error("CONNECT is not supported by this proxy");
        }

        if (!(path = parse_url(purl, hostname, &portno, &proto))) {
            error("Did not understand URL");
        }
        if (proto != 80 && proto != 443) {
            error("Unsupported protocol");
        }

        if (upgrayedd && proto == 80) {
            proto = 443;
            if (portno == 80) portno = 443;
        }

        if (http09) {
            /* convert into an HTTP/1.0 request, headers suppressed */

            buffer = malloc(strlen(hostname) + strlen(path) + 256);
            if (proto != portno) {
                (void)sprintf(buffer,
                              "GET %s HTTP/1.0\r\n"
                              "Host: %s:%d\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                (strlen(path) ? path : "/"), hostname, portno);
            } else {
                (void)sprintf(buffer,
                              "GET %s HTTP/1.0\r\n"
                              "Host: %s\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                (strlen(path) ? path : "/"), hostname);
            }
        } else {
            /* HTTP/1.0 or 1.1. read the rest of the headers */
            char *has_host;
            char hosthost[512], hostport[512];
            int crlf = 0;

            read_size = 0;
            numcrs = 0;
            with_headers = 1;

            for(;;) {
                c = fgetc(stdin);
                read_buffer[read_size++] = c;
                if (read_size == 65536) return 1; /* overflow */

                if (c == '\n') {
                    if (++numcrs == 2) break; else continue;
                }
                if (c == '\r') continue;
                numcrs = 0;
            }
            numcrs = 0;
            if (read_size < 4) return 1; /* unpossible */
            if (read_buffer[(read_size-1)] == read_buffer[(read_size-2)]) {
                /* ends in \n\n, hmm */
                read_buffer[(read_size-1)] = '\0';
            } else if (read_buffer[(read_size-4)] == '\r' &&
                   read_buffer[(read_size-1)] == read_buffer[(read_size-3)]) {
                /* can only end in \r\n\r\n */
                read_buffer[(read_size-2)] = '\0';
                crlf = 1;
            } else return 1; /* huh? */

            /* compute host header. we need to either add it or check it.
               some clients will append :80 (WebTV), so generate both. */
            (void)sprintf(hostport, "Host: %s:%d%s",
                          hostname, portno, (crlf) ? "\r\n" : "\n");
            (void)sprintf(hosthost, "Host: %s%s",
                          hostname, (crlf) ? "\r\n" : "\n");

            if (has_host = strstr((char *)read_buffer, "Host: ")) {
                /* to make this simpler, RFC 7230 gives us a way to cheat.
                   if there is a Host: header here, it must match the hostname
                   in the URL. if it doesn't, abort. */

                /* multiple Host: headers? eat my shorts. */
                if (strstr(++has_host, "Host: ")) return 1;

                /* header is bogus? eat more of my shorts. */
		if (proto != portno) { /* only allow host:port */
                    if (!strstr((char *)read_buffer, hostport)) return 1;
                } else { /* allow either */
                    if (!strstr((char *)read_buffer, hosthost) &&
                        !strstr((char *)read_buffer, hostport)) return 1;
                }

                /* acceptable; use client header set */
                buffer = malloc(strlen(method) + strlen(path) +
                                strlen((char *)read_buffer) + 256);
                (void)sprintf(buffer, "%s %s %s%s",
                              method, (strlen(path) ? path : "/"),
                              read_buffer, (crlf) ? "\r\n" : "\n");
            } else {
                /* add Host: header */
                buffer = malloc(strlen(method) + strlen(path) +
                                strlen((char *)read_buffer) +
                                strlen((portno != proto) ? hostport :
                                                           hosthost) + 256);
                (void)sprintf(buffer, "%s %s %s%s%s",
                              method, (strlen(path) ? path : "/"),
                              read_buffer,
                              (portno != proto) ? hostport : hosthost,
                              (crlf) ? "\r\n" : "\n");
            }
        }
    } else {
        /* url provided on command line */

        if (!(path = parse_url(url, hostname, &portno, &proto))) {
            if (!quiet) fprintf(stderr, "%s: couldn't parse url\n", argv[0]);
            return 1;
        }
        if (proto == 1080) {
            if (!quiet) fprintf(stderr, "%s: socks only allowed for proxies\n",
                                argv[0]);
            return 1;
        }
        if (proto != 80 && proto != 443) {
            if (!quiet) fprintf(stderr, "%s: unsupported protocol\n", argv[0]);
            return 1;
        }

        if (upgrayedd && proto == 80) {
            proto = 443;
            if (portno == 80) portno = 443;
        }

        buffer = malloc(strlen(hostname) + strlen(path) + 256);
        if (proto != portno) {
            (void)sprintf(buffer,
"%s %s HTTP/1.0\r\n"
"Host: %s:%d\r\n"
"Connection: close\r\n"
"\r\n",
            (head_only ? "HEAD" : "GET"), (strlen(path) ? path : "/"),
             hostname, portno);
        } else {
            (void)sprintf(buffer,
"%s %s HTTP/1.0\r\n"
"Host: %s\r\n"
"Connection: close\r\n"
"\r\n",
            (head_only ? "HEAD" : "GET"), (strlen(path) ? path : "/"),
             hostname);
        }
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, timeout);
    if (!forever) (void)alarm(10);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        if (proxy) error("Host not found");
        if (!quiet) fprintf(stderr, "host not found: %s\n", hostname);
        exit(2);
    }
    memset((char *) &serv_addr, 0, sizeof(serv_addr)); /* blocking socket */
    serv_addr.sin_family = AF_INET;

    if (proxyurl) {

        /* basic socks 4 client, no NO_PROXY support yet */

        if (parse_url(proxyurl, sockshost, &socksport, &socksproto)) {
            unsigned char spacket[9];
            size_t sbytes = 0;

            if (socksproto != 1080) {
                if (!quiet) fprintf(stderr, "unsupported proxy protocol\n");
                exit(2);
            }
            if (server->h_length != 4) {
                if (!quiet) fprintf(stderr, "IPv6 not supported for SOCKS4\n");
                exit(3);
            }

            spacket[0] = 0x04; /* socks v4 */
            spacket[1] = 0x01; /* connect  */
            spacket[2] = portno >> 8;
            spacket[3] = portno & 0xff;
            spacket[4] = (unsigned char)server->h_addr[0]; 
            spacket[5] = (unsigned char)server->h_addr[1]; 
            spacket[6] = (unsigned char)server->h_addr[2]; 
            spacket[7] = (unsigned char)server->h_addr[3]; 
            spacket[8] = 0x00;

            socksserver = gethostbyname(sockshost);
            if (socksserver == NULL) {
                if (!quiet) fprintf(stderr, "SOCKS proxy not found: %s\n",
                                            sockshost);
                exit(2);
            }
            memcpy((char *)&serv_addr.sin_addr.s_addr,
                   (char *)socksserver->h_addr, socksserver->h_length);
            serv_addr.sin_port = htons(socksport);
            if (connect(sockfd,(struct sockaddr *)&serv_addr,
                        sizeof(serv_addr)) < 0) 
                error("connect to SOCKS");

            /* we should be able to send this much without blocking */
            if (send(sockfd, spacket, 9, 0) != 9)
                error("send to SOCKS");

            while ((read_size = recv(sockfd, (char *)&spacket[sbytes],
                                     9-sbytes, 0)) > 0) {
                sbytes += read_size;
                if (sbytes == 8) break;
            }

            if (sbytes != 8 || spacket[0] != 0x00 ||
                    spacket[1] < 0x5a || spacket[1] > 0x5d) {
                error("SOCKS connect failed");
                return 1;
            }
            if (spacket[1] != 0x5a) {
                if (proxy) error("SOCKS connect failed");
                if (!quiet) fprintf(stderr, "SOCKS connect: %i\n", spacket[1]);
                return 1;
            }
            proxycon = 1;
        } else {
            error("illegal proxy URL");
            return 1;
        }
    }

    /* connect to host */
                
    if (!proxycon) {
        memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
        serv_addr.sin_port = htons(portno);
        if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
           error("connect");
    }

    /* set up http or tls */

    if (proto == 443) {
        context = tls_create_context(0, TLS_V12);
        if (!tls_sni_set(context, hostname)) error("TLS context failure");
        tls_client_connect(context);
        https_send_pending(sockfd, context);
    } else {
        /* on plain HTTP, try to send the initial request right now */
        size_t buffer_index = 0;
        size_t buffer_len = strlen(buffer);

        while (buffer_len) {
            int res = send(sockfd, (char *)&buffer[buffer_index],
                           buffer_len, 0);
            if (res > 0) {
                buffer_len -= res;
                buffer_index += res;
            }
        }
    }

    /* read from socket and, if needed, stdin */

    if (proto == 80) {
        for(;;) {
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            FD_SET(STDIN_FILENO, &fdset);

            if (!forever) (void)alarm(10);
            (void)select(sockfd + 1, &fdset, NULL, NULL, NULL); /* wait */

            /* send any post-headers data, like POST forms, etc. */
            if (FD_ISSET(STDIN_FILENO, &fdset)) {
                size_t buffer_index = 0;

                read_size = fread(read_buffer, 1, 0xffff, stdin);
                while (read_size) {
                    int res = send(sockfd, (char *)&read_buffer[buffer_index],
                                   read_size, 0);
                    if (res > 0) {
                        read_size -= res;
                        buffer_index += res;
                    }
                }
            }

            if (FD_ISSET(sockfd, &fdset)) {
                if ((read_size = recv(sockfd, client_message, sizeof(client_message) , 0)) > 0) {
                    bytesread += read_size;
                    if (!with_headers) {
                        size_t i = 0;

                        for(i=0; i<read_size; i++) {
                            if (client_message[i] == '\r') continue;
                            if (client_message[i] == '\n') numcrs++;
                                else numcrs = 0;
                            if (numcrs == 2) { break; }
                        }
                        if (numcrs < 2) continue;
                        with_headers = 1; spoof10 = 0; /* paranoia */
                        for(i++; i<read_size; i++) 
                            fwrite(&(client_message[i]), 1, 1, stdout);
                    } else {
                        if (spoof10) {
                            if (read_size > 7 &&
                                    client_message[0] == 'H' &&
                                    client_message[1] == 'T' &&
                                    client_message[2] == 'T' &&
                                    client_message[3] == 'P' &&
                                    client_message[4] == '/' &&
                                    client_message[5] == '1' &&
                                    client_message[6] == '.' &&
                                    client_message[7] == '1') {
                                client_message[7] = '0';
                                spoof10 = 0;
                            }
                        }
                        fwrite(client_message, read_size, 1, stdout);
                    }
                } else break; /* ready socket, no bytes: connection closed */
            }

            /* some sort of signal, loop around */
        }
    } else if (proto == 443) {
        for(;;) {
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            FD_SET(STDIN_FILENO, &fdset);

            if (!forever) (void)alarm(10);
            (void)select(sockfd + 1, &fdset, NULL, NULL, NULL); /* wait */

            /* service socket first, since we may still be setting up TLS */
            if (FD_ISSET(sockfd, &fdset)) {
                if ((read_size = recv(sockfd, client_message, sizeof(client_message) , 0)) > 0) {
                    tls_consume_stream(context, client_message, read_size, validate_certificate);
                    https_send_pending(sockfd, context);

                    /* no point in anything further until TLS established */
                    if (!tls_established(context)) continue;

                    /* TLS up, try to send initial portion of request now */
                    if (!sent) {
                        tls_write(context, (unsigned char *)buffer, strlen(buffer));
                        https_send_pending(sockfd, context);
                        sent = 1;
                    }
                    read_size = tls_read(context, read_buffer, 0xFFFF - 1);
                    bytesread += read_size;
                    if (read_size) {
                        if (!with_headers) {
                            size_t i = 0;

                            for(i=0; i<read_size; i++) {
                                if (read_buffer[i] == '\r') continue;
                                if (read_buffer[i] == '\n') numcrs++;
                                    else numcrs = 0;
                                if (numcrs == 2) { break; }
                            }
                            if (numcrs < 2) continue;
                            with_headers = 1; spoof10 = 0; /* paranoia */
                            for(i++; i<read_size; i++) 
                                fwrite(&(read_buffer[i]), 1, 1, stdout);
                        } else {
                            if (spoof10) {
                                if (read_size > 7 &&
                                        read_buffer[0] == 'H' &&
                                        read_buffer[1] == 'T' &&
                                        read_buffer[2] == 'T' &&
                                        read_buffer[3] == 'P' &&
                                        read_buffer[4] == '/' &&
                                        read_buffer[5] == '1' &&
                                        read_buffer[6] == '.' &&
                                        read_buffer[7] == '1') {
                                    read_buffer[7] = '0';
                                    spoof10 = 0;
                                }
                            }
                            fwrite(read_buffer, read_size, 1, stdout);
                        }
                    }
                } else break; /* ready socket, no bytes: connection closed */
            }

            /* send any post-headers data, like POST forms, etc. */
            if (FD_ISSET(STDIN_FILENO, &fdset) && sent) {
                size_t buffer_index = 0;

                /* no point until TLS is established */
                if (!tls_established(context)) continue;

                read_size = fread(read_buffer, 1, 0xffff, stdin);
                tls_write(context, (unsigned char *)read_buffer, read_size);
                https_send_pending(sockfd, context);
            }
        }
    } else { /* profit! */ }

    if (!bytesread) {
        if (proto == 443 && context->error_code) {
            (void)sprintf(read_buffer,
                          "TLS alert received: %d\n", context->error_code);
            error(read_buffer);
        }
        error("No data received");
    }
    free(buffer);
    return 0;
}
