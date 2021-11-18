
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
