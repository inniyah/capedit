/* str_to.c
 *
 * $Id: str_to.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include <stdlib.h>
#include "proto/ethernet.h"

#define RADIX_MAX 16    /* The radix is usually in the 2 to 16 range */

struct ether_addr *
ether_aton_r (const char *asc, struct ether_addr *addr)
{
  size_t cnt;

  for (cnt = 0; cnt < 6; ++cnt)
    {
      unsigned int number;
      char ch;

      ch = _tolower (*asc++);
      if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
        return NULL;
      number = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);

      ch = _tolower (*asc);
      if ((cnt < 5 && ch != ':') || (cnt == 5 && ch != '\0' && !isspace (ch)))
        {
          ++asc;
          if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
            return NULL;
          number <<= 4;
          number += isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);

          ch = *asc;
          if (cnt < 5 && ch != ':')
            return NULL;
        }

      /* Store result.  */
      addr->ether_addr_octet[cnt] = (unsigned char) number;

      /* Skip ':'.  */
      ++asc;
    }

  return addr;
}

struct ether_addr *
ether_aton (const char *asc)
{
  static struct ether_addr result;

  return ether_aton_r (asc, &result);
}



int itoa (int num, char *str, int radix)
{
  register int i, neg = 0;
  register char *p = str;
  register char *q = str;

  if (radix == 0)
    radix = 10;
   else
     if (radix < 2 || radix > RADIX_MAX)
       return (radix);

  if (num == 0)
    {
      *p++ = '0';
      *p = 0;

      return (0);
    }

  if (num < 0)
    {
      neg = 1;
      num = -num;
    }

  while (num > 0)
   {
     i = num % radix;

     if (i > 9)
       i += 7;

     *p++ = '0' + i;
     num /= radix;
   }

  if (neg)
    *p++ = '-';

  *p-- = 0;
  q = str;

  while (p > q)
   {
     i = *q;
     *q++ = *p;
     *p-- = i;
   }

  return (0);
}

