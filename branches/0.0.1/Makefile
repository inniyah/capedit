# Makefile.c
#
# $Id: Makefile 1 2010-04-11 21:04:36 vijay mohan $

# PacketSquare-capedit - Pcap Edit & Replay Tool
# By vijay mohan <vijaymohan@packetsquare.com>
# Copyright 2010 vijay mohan

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


all:	
	gcc -g proto/dns.c tags.c pcap.c fragment.c packet.c to_str.c str_to.c main.c error.c pakvalupdate.c intf.c socket.c proto/ethernet.c proto/arp.c proto/ip.c proto/icmp.c proto/igmp.c proto/udp.c proto/tcp.c -o capedit `pkg-config --cflags --libs gtk+-2.0`
