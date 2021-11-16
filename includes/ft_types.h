
# pragma once

# include <inttypes.h>

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
	O_HELP		= ((u64)1 << 0),		/* '--help' */
	O_PORT		= (O_HELP << 1),		/* '--ports' */
	O_IP		= (O_PORT << 1),		/* '--ip' */
	O_FILE		= (O_IP << 1),			/* '--file' */
	O_SPEEDUP	= (O_FILE << 1),		/* '--speedup' */
	O_S_TCPSYN	= (O_SPEEDUP << 1),		/* '-sS' : TCP SYN Scan */

	O_S_TCPCON	= (O_S_TCPSYN << 1),	/* '-sT' : TCP CONNECT Scan */
	O_S_TCPACK	= (O_S_TCPCON << 1),	/* '-sA' : TCP ACK Scan */
	O_S_TCPWIN	= (O_S_TCPACK << 1),	/* '-sW' : TCP WINDOW Scan */
	O_S_TCPMAI	= (O_S_TCPWIN << 1),	/* '-sM' : TCP MAIMON Scan */
	O_S_UDP		= (O_S_TCPMAI << 1),	/* '-sU' : UDP Scan */
	O_S_TCPNUL	= (O_S_UDP << 1),		/* '-sN' : TCP NULL Scan */
	O_S_TCPFIN	= (O_S_TCPNUL << 1),	/* '-sF' : TCP FIN Scan */
	O_S_TCPXMA	= (O_S_TCPFIN << 1),	/* '-sX' : TCP XMAS Scan */
	O_S_TCPCUS	= (O_S_TCPXMA << 1),	/* '--scanflasg' : Custom TCP options Scan */
	O_S_SCTPIN	= (O_S_TCPCUS << 1),	/* '-sY' : SCTP INIT Scan */
	O_S_SCTPCE	= (O_S_SCTPIN << 1),	/* '-sZ' : SCTP COOKIE-ECHO Scan */
	O_S_IPPROT	= (O_S_SCTPCE << 1),	/* '-sO' : IP PROTOCOL Scan */

	O_VE_UP		= (O_S_IPPROT << 1),	/* '-sV' : Service and Version detection up */
	O_VE_LIGHT	= (O_VE_UP << 1),		/* '--version-light' : Alias for '-sV' */
	O_VE_ALL	= (O_VE_LIGHT << 1),	/* '--version-all' : Try all probes to find version */

	O_OS_UP		= (O_VE_ALL << 1),		/* '-O' : OS detection up */
	O_OS_LIM	= (O_OS_UP << 1),		/* '--osscan-limit' : OS detection if has almost 1 port open and closed */
	O_OS_GSS	= (O_OS_LIM << 1),		/* '--osscan-guess' : Guess OS if not perfect match */
	O_OS_MTR	= (O_OS_GSS << 1),		/* '--max-os-tries' : Max amount of tries whether there's not OS match */

	O_EV_MTU	= (O_OS_MTR << 1),		/* '--mtu' set the MTU size */
	O_EV_FRG	= (O_EV_MTU << 1),		/* '-f' : Fragments packets using '--mtu' */
	O_EV_DEC	= (O_EV_FRG << 1),		/* '-D' : Cloak a scan with decoys */
	O_EV_IP		= (O_EV_DEC << 1),		/* '-S' : Spoof source address */
	O_EV_IF		= (O_EV_IP << 1),		/* '-e' : Select interface */
	O_EV_SPRT	= (O_EV_IF << 1),		/* '-g' : Spoof source port number */
	O_EV_HDAT	= (O_EV_SPRT << 1),		/* '--data-hex' : Append custom hex string to packets */
	O_EV_SDAT	= (O_EV_HDAT << 1),		/* '--data-string' : Append custom string to packets */
	O_EV_RDAT	= (O_EV_SDAT << 1),		/* '--data-lenght' : Append random data to packets */
	O_EV_IPOP	= (O_EV_RDAT << 1),		/* '--ip-options' : Set ip options of outcoming packets */
	O_EV_TTL	= (O_EV_IPOP << 1),		/* '--ttl' : Set the ttl of outgoing packets */
	O_EV_RHST	= (O_EV_TTL << 1),		/* '--randomize-hosts' : Randomize target order */
	O_EV_MAC	= (O_EV_RHST << 1),		/* '--spoof-mac' : Spoof MAC address */
	O_EV_BSUM	= (O_EV_MAC << 1)		/* '--badsum' : Send packets with a bogus checksum */
}				parse_opts_t;

typedef struct	ft_args
{
	u16*			ports;
	u16				currport;
	u16				lastport;
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
