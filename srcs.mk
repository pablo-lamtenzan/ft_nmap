INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	ft_error.h\
	ft_libc.h\
	ft_nmap.h\
	ft_parse.h\
	ft_types.h\
	ft_utils.h\
)
SRCS	=\
$(addprefix srcs/,\
	main.c\
	$(addprefix parse/,\
		parse.c\
		parse_port.c\
	)\
)
