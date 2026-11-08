/* Host shim: lwIP options for compiling wireguard-lwip against IDF's lwIP headers.
 * Only the headers are used; test_wg.c supplies the few lwIP functions it links. */
#pragma once
#define NO_SYS 1
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_UDP 1
#define LWIP_TCP 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_CHECKSUM_CTRL_PER_NETIF 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 1
