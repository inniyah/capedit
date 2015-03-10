PROGRAM=capedit

all: $(PROGRAM)

SOURCES = \
	proto/dns.c \
	tags.c pcap.c \
	fragment.c \
	packet.c \
	to_str.c \
	str_to.c \
	main.c \
	error.c \
	pakvalupdate.c \
	intf.c \
	socket.c \
	proto/ethernet.c \
	proto/arp.c \
	proto/ip.c \
	proto/icmp.c \
	proto/igmp.c \
	proto/udp.c \
	proto/tcp.c

OBJS = $(SOURCES:.c=.o)

CFLAGS= -O2 -g -Wall
INCS=-I.
DEFS=

LDFLAGS= -Wl,-z,defs -Wl,--as-needed -Wl,--no-undefined
LIBS=

PKG_CONFIG=gtk+-2.0
PKG_CONFIG_CFLAGS=`pkg-config --cflags $(PKG_CONFIG)`
PKG_CONFIG_LIBS=`pkg-config --libs $(PKG_CONFIG)`

INCS+=$(PKG_CONFIG_CFLAGS)
LIBS+=$(PKG_CONFIG_LIBS)

$(PROGRAM): $(OBJS)
	g++ $(LDFLAGS) $+ -o $@ $(LIBS)

%.o: %.cpp
	g++ -o $@ $(DEFS) $(INCS) -c $+ $(CFLAGS)

%.o: %.c
	gcc -o $@ $(DEFS) $(INCS) -c $+ $(CFLAGS)

clean:
	rm -f $(OBJS)
	rm -f $(PROGRAM)
	rm -f *.o *.a *~

