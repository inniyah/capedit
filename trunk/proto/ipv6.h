#ifndef _NETINET_IPV6_H_
#define _NETINET_IPV6_H_
#include<stdint.h>


/* IPv6 address */
struct inipv6_addr
  {
    union
      {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
      } __in6_u;
  };


struct ip6hdr {
    uint32_t  vtf;
    uint16_t  payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct  inipv6_addr saddr;
    struct  inipv6_addr daddr;
    /*The options start here. */
};
uint8_t
display_ipv6(uint8_t **pak);

void
update_ipv6(char *value);
/* IPv6 address */


#endif

