/* intf.c
 *
 * $Id: intf.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>



int intf_list(char intf[][10])
{
   struct ifconf ifconf;
   static struct ifreq ifreqs[20];
   int  nifaces = 0, i;


   int sock;

   memset(intf,0,sizeof(intf[20][10]));
   memset(&ifconf,0,sizeof(ifconf));
   ifconf.ifc_buf = (char*) (ifreqs);
   ifconf.ifc_len = sizeof(ifreqs);

   sock = socket(AF_INET,SOCK_STREAM,0);
   if(sock < 0)
   {
     perror("socket");
     return (-1);
   }

   if((ioctl(sock, SIOCGIFCONF , (char *) &ifconf  )) < 0 )
     perror("ioctl(SIOGIFCONF)");

   nifaces =  ifconf.ifc_len/sizeof(struct ifreq);
   for(i = 0; i < nifaces; i++)
   {
     strcpy(intf[i],ifreqs[i].ifr_name);
   }


   close(sock);

   return nifaces;
}

/*main()
{
	char intf[20][10];	
	int i, j;	

	j = intf_list(intf);

   for(i = 0; i < j; i++)
   {
     printf("%s\n", intf[i]);
   }

} */
