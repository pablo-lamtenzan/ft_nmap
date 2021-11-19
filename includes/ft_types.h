
# pragma once

# include <inttypes.h>
# include <stdbool.h>

typedef int8_t		i8;
typedef int16_t		i16;
typedef int32_t		i32;
typedef int64_t		i64;

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

typedef enum	parse_opts
{
	O_HELP		= ((u64)1UL << 0),			/* '--help' */
	O_FULLPORT	= ((u64)O_HELP << 1),		/* '--port-max=unlimited */
	O_PORT		= ((u64)O_FULLPORT << 1),	/* '--ports' */
	O_IP		= ((u64)O_PORT << 1),		/* '--ip' */
	O_FILE		= ((u64)O_IP << 1),			/* '--file' */
	O_SPEEDUP	= ((u64)O_FILE << 1),		/* '--speedup' */

	O_S_TCPSYN	= ((u64)O_SPEEDUP << 1),	/* '-sS' : TCP SYN Scan */
	O_S_TCPCON	= ((u64)O_S_TCPSYN << 1),	/* '-sT' : TCP CONNECT Scan */
	O_S_TCPACK	= ((u64)O_S_TCPCON << 1),	/* '-sA' : TCP ACK Scan */
	O_S_TCPWIN	= ((u64)O_S_TCPACK << 1),	/* '-sW' : TCP WINDOW Scan */
	O_S_TCPMAI	= ((u64)O_S_TCPWIN << 1),	/* '-sM' : TCP MAIMON Scan */
	O_S_UDP		= ((u64)O_S_TCPMAI << 1),	/* '-sU' : UDP Scan */
	O_S_TCPNUL	= ((u64)O_S_UDP << 1),		/* '-sN' : TCP NULL Scan */
	O_S_TCPFIN	= ((u64)O_S_TCPNUL << 1),	/* '-sF' : TCP FIN Scan */
	O_S_TCPXMA	= ((u64)O_S_TCPFIN << 1),	/* '-sX' : TCP XMAS Scan */
	O_S_TCPCUS	= ((u64)O_S_TCPXMA << 1),	/* '--scanflags' : Custom TCP options Scan */
	O_S_SCTPIN	= ((u64)O_S_TCPCUS << 1),	/* '-sY' : SCTP INIT Scan */
	O_S_SCTPCE	= ((u64)O_S_SCTPIN << 1),	/* '-sZ' : SCTP COOKIE-ECHO Scan */
	O_S_IPPROT	= ((u64)O_S_SCTPCE << 1),	/* '-sO' : IP PROTOCOL Scan */

	O_VE_UP		= ((u64)O_S_IPPROT << 1),	/* '-sV' : Service and Version detection up */
	O_VE_LIGHT	= ((u64)O_VE_UP << 1),		/* '--version-light' : Alias for '-sV' */
	O_VE_ALL	= ((u64)O_VE_LIGHT << 1),	/* '--version-all' : Try all probes to find version */

	O_OS_UP		= ((u64)O_VE_ALL << 1),		/* '-O' : OS detection up */
	O_OS_LIM	= ((u64)O_OS_UP << 1),		/* '--osscan-limit' : OS detection if has almost 1 port open and closed */
	O_OS_GSS	= ((u64)O_OS_LIM << 1),		/* '--osscan-guess' : Guess OS if not perfect match */
	O_OS_MTR	= ((u64)O_OS_GSS << 1),		/* '--max-os-tries' : Max amount of tries whether there's not OS match */

	O_EV_MTU	= ((u64)O_OS_MTR << 1),		/* '--mtu' set the MTU size */
	O_EV_FRG	= ((u64)O_EV_MTU << 1),		/* '-f' : Fragments packets using '--mtu' */
	O_EV_DEC	= ((u64)O_EV_FRG << 1),		/* '-D' : Cloak a scan with decoys */
	O_EV_IP		= ((u64)O_EV_DEC << 1),		/* '-S' : Spoof source address */
	O_EV_IF		= ((u64)O_EV_IP << 1),		/* '-e' : Select interface */
	O_EV_SPRT	= ((u64)O_EV_IF << 1),		/* '-g' : Spoof source port number */
	O_EV_HDAT	= ((u64)O_EV_SPRT << 1),	/* '--data-hex' : Append custom hex string to packets */
	O_EV_SDAT	= ((u64)O_EV_HDAT << 1),	/* '--data-string' : Append custom string to packets */
	O_EV_RDAT	= ((u64)O_EV_SDAT << 1),	/* '--data-lenght' : Append random data to packets */
	O_EV_IPOP	= ((u64)O_EV_RDAT << 1),	/* '--ip-options' : Set ip options of outcoming packets */
	O_EV_TTL	= ((u64)O_EV_IPOP << 1),	/* '--ttl' : Set the ttl of outgoing packets */
	O_EV_RHST	= ((u64)O_EV_TTL << 1),		/* '--randomize-hosts' : Randomize target order */
	O_EV_MAC	= ((u64)O_EV_RHST << 1),	/* '--spoof-mac' : Spoof MAC address */
	O_EV_BSUM	= ((u64)O_EV_MAC << 1)		/* '--badsum' : Send packets with a bogus checksum */
}				parse_opts_t;

typedef enum portpref
{
	PREF_NONE,
	PREF_TCP,
	PREF_UDP,
	PREF_SCTP,
	PREF_ERROR
}			portpref_t;

typedef struct	ft_port
{
	portpref_t	preffix;
	u16			value;
}				port_t;

typedef struct	ft_args
{
	port_t*			ports;
	u16				currport;
	u64				totalports;
	bool			no_port_iterations;
	u32*			ips;
	u32				currip;
	u32				lastip;
	i8*				file;
	u16				nb_threads;
	u8				os_det_tries;
	u64				mtu;
	void*			decoys; // TODO: define type (a kind of array)
	u32				scr_ipaddr;
	u8*				interface;
	u16				scr_port;
	u8*				data;
	u8*				ip_opts;
	u8				ttl;
	u8*				src_mac;
}				args_t;

typedef struct	ft_parse
{
	u64			opts;
	args_t		args;
}				parse_t;
