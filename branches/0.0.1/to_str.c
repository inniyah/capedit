/* to_str.c
 *
 * $Id: to_str.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include"to_str.h"

char *
bytestring_to_str(const uint8_t *ad, uint32_t len, char punct) 
{
  char *buf;
  char        *p;
  int          i = (int) len - 1;
  uint32_t      octet;
  size_t       buflen;
  /* At least one version of Apple's C compiler/linker is buggy, causing
 *      a complaint from the linker about the "literal C string section"
 *           not ending with '\0' if we initialize a 16-element "char" array with
 *                a 16-character string, the fact that initializing such an array with
 *                     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
 *                          '\0' byte in the string nonwithstanding. */
  static const char hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  if (punct)
    buflen=len*3;
  else
    buflen=len*2 + 1;

  if (buflen < 3 || i < 0) {
    return "";
  }

  buf=(char *)malloc(buflen);
  p = &buf[buflen - 1];
  *p = '\0';
  for (;;) {
    octet = ad[i];
    *--p = hex_digits[octet&0xF];
    octet >>= 4;
    *--p = hex_digits[octet&0xF];
    if (i <= 0)
      break;
    if (punct)
      *--p = punct;
    i--;
  }
  return p;
}

char *
ether_to_str(uint8_t *ad)
{
        return bytestring_to_str(ad, 6, ':');
}

/*
 *  This function is very fast and this function is called a lot.
 *   XXX update the address_to_str stuff to use this function.
 *   */
static const char * const fast_strings[] = {
"0", "1", "2", "3", "4", "5", "6", "7",
"8", "9", "10", "11", "12", "13", "14", "15",
"16", "17", "18", "19", "20", "21", "22", "23",
"24", "25", "26", "27", "28", "29", "30", "31",
"32", "33", "34", "35", "36", "37", "38", "39",
"40", "41", "42", "43", "44", "45", "46", "47",
"48", "49", "50", "51", "52", "53", "54", "55",
"56", "57", "58", "59", "60", "61", "62", "63",
"64", "65", "66", "67", "68", "69", "70", "71",
"72", "73", "74", "75", "76", "77", "78", "79",
"80", "81", "82", "83", "84", "85", "86", "87",
"88", "89", "90", "91", "92", "93", "94", "95",
"96", "97", "98", "99", "100", "101", "102", "103",
"104", "105", "106", "107", "108", "109", "110", "111",
"112", "113", "114", "115", "116", "117", "118", "119",
"120", "121", "122", "123", "124", "125", "126", "127",
"128", "129", "130", "131", "132", "133", "134", "135",
"136", "137", "138", "139", "140", "141", "142", "143",
"144", "145", "146", "147", "148", "149", "150", "151",
"152", "153", "154", "155", "156", "157", "158", "159",
"160", "161", "162", "163", "164", "165", "166", "167",
"168", "169", "170", "171", "172", "173", "174", "175",
"176", "177", "178", "179", "180", "181", "182", "183",
"184", "185", "186", "187", "188", "189", "190", "191",
"192", "193", "194", "195", "196", "197", "198", "199",
"200", "201", "202", "203", "204", "205", "206", "207",
"208", "209", "210", "211", "212", "213", "214", "215",
"216", "217", "218", "219", "220", "221", "222", "223",
"224", "225", "226", "227", "228", "229", "230", "231",
"232", "233", "234", "235", "236", "237", "238", "239",
"240", "241", "242", "243", "244", "245", "246", "247",
"248", "249", "250", "251", "252", "253", "254", "255"
};

void
ip_to_str_buf(const uint8_t *ad, char *buf, int buf_len)
{
        register char const *p;
        register char *b=buf;

        if (buf_len < MAX_IP_STR_LEN) {
                printf ( " BUF_TOO_SMALL_ERR ");                 /* Let the unexpected value alert user */
                return;
        }

        p=fast_strings[*ad++];
        do {
                *b++=*p;
                p++;
        } while(*p);
        *b++='.';

        p=fast_strings[*ad++];
        do {
                *b++=*p;
                p++;
        } while(*p);
        *b++='.';

        p=fast_strings[*ad++];
        do {
                *b++=*p;
                p++;
        } while(*p);
        *b++='.';

        p=fast_strings[*ad];
        do {
                *b++=*p;
                p++;
        } while(*p);
        *b=0;
}

/*
 *  *  This function is very fast and this function is called a lot.
 *   *   XXX update the address_to_str stuff to use this function.
 *    *   */
char *
ip_to_str(uint8_t *ad) {
  char *buf;

  buf=(char *)malloc(MAX_IP_STR_LEN);
  ip_to_str_buf(ad, buf, MAX_IP_STR_LEN);
  return buf;
}

