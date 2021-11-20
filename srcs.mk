INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	debug.h\
	ft_error.h\
	ft_libc.h\
	ft_nmap.h\
	ft_parse.h\
	ft_types.h\
	ft_utils.h\
)
SRCS	=\
$(addprefix srcs/,\
	$(addprefix analyse/,\
	)\
	$(addprefix debug/,\
		dbg_print_ips.c\
		dbg_print_ports.c\
	)\
	$(addprefix engine/,\
	)\
	$(addprefix ft_libc/,\
		split.c\
	)\
	main.c\
	$(addprefix parse/,\
		free_parse.c\
		parse.c\
		parse_ip.c\
		parse_port.c\
	)\
)
