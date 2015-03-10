/* dns.c
*
* $Id: dns.c 1 2010-04-11 21:04:36 vijay mohan $
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
*along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/

#include<stdio.h>
#include<stdint.h>
#include"../main.h"
#include<stdlib.h>
#include"../pakvalupdate.h"
#include "../packet.h"
#include "dns.h"


void FromDnsNameFormat(uint8_t** outhost) {
        //convert 3www6google3com0 to www.google.com
         uint8_t i = 0, j,p,*tmp_string;
	 char count[2];
	 uint8_t *tmp_buf = *outhost;
	 uint8_t t =0;
	 
	tmp_string = (uint8_t *)malloc(255);	 

         while(*tmp_buf != 0)
         {
		t = *tmp_buf;
		++tmp_buf;
               	for(j=0;j < t;j++) {
                        tmp_string[i] = *tmp_buf;
			++i;
			++tmp_buf;
		}
		tmp_string[i] = '.';
		i++;
         }
	 tmp_string[i-1] = '\0';
	//free(*outhost);
	*outhost = tmp_string;
}


uint8_t * ReadName(uint8_t* reader,uint8_t* buffer,uint8_t* count) {
        uint8_t* name;
        uint16_t p=0,jumped=0,offset;
	uint8_t i =0;
	*count = 1;
	name = (uint8_t *)malloc(255);
        //read the names in 3www6google3com format
         while(*reader!=0) {
                 if(*reader>=192) {
                        offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000  ;)
			reader = buffer + offset ;//- 1;
                        jumped = 1;  //we have jumped to another location so counting wont go up!
                 } else {
                         *(name+i) = *reader++;
			 i += 1;
			 if (jumped == 0)
			 {
				*count = *count + 1;
			 }

		 }

	  }
	 *(name+i) = 0;

	 if (jumped == 1){
                *count = *count + 1;
         }

         // now convert 3www6google3com0
        // printf("%s\n",name); 
         FromDnsNameFormat(&name);
         return name;

}


void
display_dns(uint8_t **pak)
{
	uint8_t temp;
	struct dnshdr  *dns_hdr;
	struct query dns_query[20];
	struct res_record answers[20],auth[20],addit[20];  //the replies from the DNS server
	uint8_t *name;

	dns_hdr = (struct dnshdr *)*pak;
	ptree_append ("Domain Name Service (DNS)",NULL,STRING, 0, P_DNS, 0);
        ptree_append ("Identification:", &dns_hdr->id ,UINT16D,1, P_DNS, 0);
	ptree_append ("Flags:",&dns_hdr->flags, UINT16_HEX, 1, P_DNS, 0);

        temp = pak_get_bits_uint16(dns_hdr->flags,15,1);
        ptree_append ("Query/Response:",&temp, UINT8,2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,14,4);
        ptree_append ("Opcode:",&temp, UINT8, 2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,10,1);
        ptree_append ("Authoritive Answer:",&temp, UINT8, 2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,9,1);
        ptree_append ("Truncated Flag:",&temp,UINT8,2, P_DNS, 0);
	temp = pak_get_bits_uint16(dns_hdr->flags,8,1);
        ptree_append ("Recursioni Desired:",&temp,UINT8,2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,7,1);
        ptree_append ("Recursion Available:",&temp,UINT8,2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,6,3);
        ptree_append ("Reserved:",&temp,UINT8,2, P_DNS, 0);
        temp = pak_get_bits_uint16(dns_hdr->flags,3,4);
        ptree_append ("Response Code",&temp,UINT8,2, P_DNS, 0);

        ptree_append ("Question Count:",&dns_hdr->q_count, UINT16, 1, P_DNS, 0);
        ptree_append ("Answer Count:",&dns_hdr->ans_count, UINT16,1, P_DNS, 0);
        ptree_append ("Authority Count:",&dns_hdr->auth_count, UINT16,1, P_DNS, 0);
        ptree_append ("Resource Count:",&dns_hdr->add_count, UINT16,1, P_DNS, 0);
	
	//reading query
        uint8_t i,stop=0;
	uint8_t* tmp_buf = (uint8_t *)(*pak+sizeof(struct dnshdr));
	
        for(i=0;i<ntohs(dns_hdr->q_count);i++)
	{
	        name=ReadName(tmp_buf ,(uint8_t *)*pak,&stop);
		ptree_append ("Queries",NULL,STRING,1, P_DNS, 0);
		ptree_append ("Name",name,STRING_P,2, P_DNS, 0);
		tmp_buf += stop;
		ptree_append ("Type",tmp_buf,UINT16,2, P_DNS, 0);
		tmp_buf += sizeof(uint16_t);
		ptree_append ("Class",tmp_buf,UINT16,2, P_DNS, 0);
		tmp_buf += sizeof(uint16_t);
	}
	
	for(i=0;i<ntohs(dns_hdr->ans_count);i++)
	{
        	ptree_append ("Answers",NULL,STRING,1, P_DNS, 0);
		getres_record(&tmp_buf,pak);
	}
	/*for(i=0;i<ntohs(dns_hdr->auth_count);i++)
        {
	        ptree_append ("Authority records",NULL,STRING,1, P_DNS, 0);
                getres_record(&tmp_buf,pak);
        }
	for(i=0;i<ntohs(dns_hdr->add_count);i++)
        {
        	ptree_append ("Additional Records",NULL,STRING,1, P_DNS, 0);
                getres_record(&tmp_buf,pak);
        }*/

}	

void
getres_record(uint8_t** tmp_buf, uint8_t** pak)
{
	uint8_t stop=0,*name;
        name=ReadName(*tmp_buf ,(uint8_t *)*pak,&stop);
        ptree_append ("Name",name,STRING_P,2, P_DNS, 0);
        *tmp_buf += stop;
		
	uint16_t type = ntohs(*(uint16_t *)*tmp_buf);
        ptree_append ("Type",*tmp_buf,UINT16,2, P_DNS, 0);
        *tmp_buf += sizeof(uint16_t);
                
	ptree_append ("Class",*tmp_buf,UINT16,2, P_DNS, 0);
        *tmp_buf += sizeof(uint16_t);
		
	//printf("%x\n",(*(uint32_t *)tmp_buf));
        ptree_append ("TTL",*tmp_buf,UINT32,2, P_DNS, 0);
        *tmp_buf += sizeof(uint32_t);
		
	uint16_t datalen = ntohs(*(uint16_t *)tmp_buf);
	//printf("%d\n",datalen);
        ptree_append ("Length",*tmp_buf,UINT16,2, P_DNS, 0);
        *tmp_buf += sizeof(uint16_t);
        //tmp_buf += datalen;

	uint8_t * rdata = (uint8_t *)malloc(datalen);
	uint8_t j;
	switch(type){
	case 1:
		//uint8_t * rdata = (uint8_t *)malloc(datalen);
		for (j = 0; j < datalen;j++){
			rdata[j] = **tmp_buf;
			*tmp_buf++;
		}	
		rdata[j] = '\0';
		ptree_append ("R Data",rdata,STRING_P,2, P_DNS, 0);
		break;
	case 15:
		printf("%d\n",stop);
		ptree_append ("pref",*tmp_buf,UINT16,2, P_DNS, 0);
		*tmp_buf += sizeof(uint16_t);
		name=ReadName(*tmp_buf ,(uint8_t *)*pak,&stop);
		ptree_append ("Name",name,STRING_P,2, P_DNS, 0);
	        *tmp_buf += stop;
		break;
	default:
                name=ReadName(*tmp_buf ,(uint8_t *)*pak,&stop);
                ptree_append ("Name",name,STRING_P,2, P_DNS, 0);
                *tmp_buf += stop;
		break;
	}

    }


/*
void ToDnsNameFormat(uint8_t** outDns) {
	//convert www.google.com to 3www6google3com
        int lock=0 , i;
        char dnsLen;
        host.append(".");
        for(i=0;i<static_cast<int>(host.length());i++) {
                if(host[i]=='.') {
                        dnsLen = i-lock;
                        outDns.push_back(dnsLen);
                        for(;lock<i;lock++)
                                outDns.push_back(host[lock]);
                        lock++;
                }
        }
}
*/

