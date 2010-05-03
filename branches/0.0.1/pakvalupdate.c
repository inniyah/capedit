/* pakvalupdate.c
 *
 * $Id: pakvalupdate.c 1 2010-04-11 21:04:36 vijay mohan $
 *
 * PacketSquare-capedit - Pcap Edit & Replay Tool
 * By vijay mohan <vijaymohan@packetsquare.com>
 * Copyright 2010 vijay mohan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include<string.h>
#include "main.h"
#include <arpa/inet.h>
#include "error.h"
#include "proto/ethernet.h"
#include "str_to.h"


unsigned int atoh(char *ap)
{
        register char *p;
        register unsigned int n;
        register int digit,lcase;

        p = ap;
        n = 0;
        while ((digit = (*p >= '0' && *p <= '9')) ||
                (lcase = (*p >= 'a' && *p <= 'f')) ||
                (*p >= 'A' && *p <= 'F')) {
                n *= 16;
                if (digit)      n += *p++ - '0';
                else if (lcase) n += 10 + (*p++ - 'a');
                else            n += 10 + (*p++ - 'A');
        }
        return(n);
}

uint32_t
getbits(uint32_t value, uint8_t position, uint8_t no_bits)
{
	return (value >> (position+1-no_bits ) & ~(~0 << no_bits));
}


uint8_t
pak_get_bits_uint8(uint8_t value, uint8_t position, uint8_t no_bits)
{
	return getbits(value, position, no_bits);
}

uint16_t
pak_get_bits_uint16(uint16_t value, uint8_t position, uint8_t no_bits)
{
        uint16_t i16;
        i16 = ntohs(value);
        return getbits(i16, position, no_bits);
}

uint32_t
pak_get_bits_uint32(uint32_t value, uint8_t position, uint8_t no_bits)
{
        uint32_t i32;
        i32 = ntohl(value);
        return getbits(i32, position, no_bits);
}

uint32_t
setbits(uint32_t value, uint8_t position, uint8_t no_bits, uint32_t val2)
{
	

	return   value & ~(~(~0 << no_bits) << (position+1-no_bits)) |
		(val2 & ~(~0 << no_bits)) << (position+1-no_bits);

}

uint8_t
pak_set_bits_uint8(uint8_t param, uint8_t position, uint8_t no_bits, char *value)
{
	uint8_t i8;
	i8 = atoh(value);
        if (no_bits == 1) {
                if (!((i8 == 0) || (i8 == 1))) {
                        err_val = 4;
                        return;
                }
        }
	return setbits(param, position, no_bits, i8);

}

uint8_t
pak_set_bits_uint8_hex(uint8_t param, uint8_t position, uint8_t no_bits, char *value)
{
	uint8_t i8;
	char buf[10];

	if (!strncasecmp("0x", value, 2)) {
		sprintf(buf, "%s", &value[2]);
		i8 = atoh(buf);
		return setbits(param, position, no_bits, i8);
	} else {
                err_val = 3;
        }
}

uint16_t
pak_set_bits_uint16(uint16_t param, uint8_t position, uint8_t no_bits, char *value)
{
	uint16_t i16;
	i16 = atoh(value);
	if (no_bits == 1) {
		if (!((i16 == 0) || (i16 == 1))) {
			err_val = 4;
			return;
		}
	}
	param = ntohs(param);
        return htons(setbits(param, position, no_bits, i16));

}

uint16_t
pak_set_bits_uint16D(uint16_t param, uint8_t position, uint8_t no_bits, char *value)
{
        uint16_t i16;
        i16 = atoi(value);
        if (no_bits == 1) {
                if (!((i16 == 0) || (i16 == 1))) {
                        err_val = 4;
                        return;
                }
        }
        param = ntohs(param);
        return htons(setbits(param, position, no_bits, i16));

}

uint32_t
pak_set_bits_uint32(uint32_t param, uint8_t position, uint8_t no_bits, char *value)
{
	uint32_t i32;
	i32 = atoh(value);
        if (no_bits == 1) {
                if (!((i32 == 0) || (i32 == 1))) {
                        err_val = 4;
                        return;
                }
        }
	param = ntohl(param);
        return htonl(setbits(param, position, no_bits, i32));

}

uint32_t
pak_set_bits_uint32D(uint32_t param, uint8_t position, uint8_t no_bits, char *value)
{
        uint32_t i32;
        i32 = atoi(value);
        if (no_bits == 1) {
                if (!((i32 == 0) || (i32 == 1))) {
                        err_val = 4;
                        return;
                }
        }
        param = ntohl(param);
        return htonl(setbits(param, position, no_bits, i32));
}


uint32_t
pak_set_bits_uint16_hex(uint16_t param, uint8_t position, uint8_t no_bits, char *value)
{
	char buf[10];
	uint16_t i16;
	if (!strncasecmp("0x", value, 2)) {
		sprintf(buf,"%s",&value[2]);
		i16 = atoh(buf);
        	param = ntohs(param);
        	return htons(setbits(param, position, no_bits, i16));
	} else {
		err_val = 3;
	}
}

uint32_t
pak_set_bits_uint32_hex(uint32_t param, uint8_t position, uint8_t no_bits, char *value)
{
        char buf[20];
        uint32_t i32;
        if (!strncasecmp("0x", value, 2)) {
                sprintf(buf,"%s",&value[2]);
                i32 = atoh(buf);
                param = ntohl(param);
                return htonl(setbits(param, position, no_bits, i32));
        } else {
                err_val = 3;
        }
}

void pak_val_update(void *param, char *value, uint16_t type)
{
	struct in_addr;
	char	 buf[20];
	char     *pc;
	char      c;
	uint8_t  *p8;
	uint8_t   i8;
	uint16_t *p16;
	uint16_t  i16;
	uint32_t *p32;
	uint32_t  i32;
	struct ether_addr *eth;
	uint8_t porf;

	if (type == UINT8) {
		p8 = (uint8_t *)param;
		*p8 = atoi(value);
	} else if (type == UINT8_HEX_2) {
                if (!strncasecmp("0x", value, 2)) {
                        p8 = (uint8_t *)param;
                        sprintf(buf, "%s", &value[2]);
                        i8 = atoh(buf);
                        *p8 = i8;
                } else {
                        err_val = 3;
                }
	} else if (type == UINT16D) {
		p16 = (uint16_t *)param;
		i16 = atoi(value);
		*p16 = htons(i16);
        } else if (type == UINT16) {
                p16 = (uint16_t *)param;
                i16 = atoi(value);
                *p16 = htons(i16);
	} else if (type == UINT16_HEX) {
		if (!strncasecmp("0x", value, 2)) {
			p16 = (uint16_t *)param;
			sprintf(buf, "%s", &value[2]);
			i16 = atoh(buf);
			i16 = ntohs(i16);
			*p16 = i16;		
		} else {
			err_val = 3;
		}
	} else if (type == UINT32D) {
                p32 = (uint32_t *)param;
                i32 = atoi(value);
                i32 = ntohl(i32);
                *p32 = i32;
	} else if (type == MAC) {
		eth = (struct ether_addr *)ether_aton(value);
		if (eth == NULL) {
			err_val = 2;
		} else {
			memcpy((uint8_t *)param, (void *)eth, sizeof(struct ether_addr));
		}
	} else if (type == IPV4_ADDR) {
		p32 = (uint32_t *)param;
		i32 = inet_addr(value);
		if (i32 != -1) {
			*p32 = i32;
		} else {
			if (!strcmp("255.255.255.255", value)) {
				*p32 = i32;
			} else {
				err_val = 1;
			}
		}
	} else if (type == IPV6_ADDR) {
		porf = inet_pton(AF_INET6, value, param);
		if (porf <= 0) {
			err_val = 5;
           	}

	}

}
