
# pragma once

# include <stdio.h>

#ifndef __progname
# define __progname "ft_nmap"
#endif

# define DEBUG_PREFFIX "[DEBUG] "

# define PRINT_ERROR(format, args...) (dprintf(2, format, args))
# define PRINT_INFO(format, args...) (dprintf(1, format, args))
# define DEBUG(format, args...) (dprintf(2, DEBUG_PREFFIX format, args))

typedef enum	ft_err
{
	SUCCESS,
	BREAK,
	ESYSCALL,
	EARGUMENT,
	EMAXRANGE,
}				err_t;

# define EMSG_PREFFFIX __progname ": error: "

# define EMSG_SYSCALL EMSG_PREFFFIX "syscall %s failed (code: %d)" "\n"
# define EMSG_INVARG EMSG_PREFFFIX "option `%s\': invalid argument `%s\'" "\n"
# define EMSG_EXPECTED_ARG EMSG_PREFFFIX "option `%s\': expects arguments" "\n"
# define EMSG_UNKNOWN_OPT EMSG_PREFFFIX "unkown option `%s\'" "\n"
# define EMSG_MAXPORTRANGE EMSG_PREFFFIX "max port range suported is %d" "\n"
# define EMSG_MAXTHREADSRANGE EMSG_PREFFFIX "max parallel scanings suported are %d" "\n"
# define EMSG_REPEATED_PORT EMSG_PREFFFIX "repeated port not allowed (repeated port: %hu)" "\n"
# define EMSG_REPEATED_IP EMSG_PREFFFIX "repeated ip not allowed (repeared ip %s)" "\n"
# define EMSG_ZEROED_IP EMSG_PREFFFIX "option `%s\': ip `0.0.0.0\' is not a valid target" "\n"
# define EMSG_BROADCAST_IP EMSG_PREFFFIX "option `%s\': ip `255.255.255.255\' is not a valid target" "\n"
# define EMSG_INV_VALUE EMSG_PREFFFIX "option `%s\': invalid value: `%s\' (valid range: %d >= <value> >= %d)" "\n"
# define EMSG_UNKOWN_FILENAME EMSG_PREFFFIX "option `%s\': unkown filename: `%s\'" "\n"
# define EMSG_INV_MTU EMSG_PREFFFIX "option --mtu: invalid value: `%s\' (must be > 0 and a multiple of 8)" "\n"
# define EMSG_NOEFFECT_SPEEDUP __progname ": warning: option `%s\': 0 has no effect" "\n"
# define EMSG_DECOY_NEEDDECOYS EMSG_PREFFFIX "option `%s\': need at least 1 decoy ip address" "\n"
# define EMGS_IMCOMPATIBLE_OPTS EMSG_PREFFFIX "options `%s\' is imcompatible with `%s\'" "\n"
# define EMGS_DUPLICATE_OPT EMSG_PREFFFIX "invalid duplicated option: `%s\'" "\n"