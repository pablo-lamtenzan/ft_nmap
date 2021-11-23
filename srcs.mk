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
		dbg_parse_opts.c\
		dbg_print_ips.c\
		dbg_print_ports.c\
	)\
	$(addprefix engine/,\
	)\
	$(addprefix ft_libc/,\
		ft_strtol.c\
		split.c\
	)\
	main.c\
	$(addprefix parse/,\
		free_parse.c\
		parse.c\
		parse_data_hex.c\
		parse_data_lenght.c\
		parse_data_string.c\
		parse_decoys.c\
		parse_file.c\
		parse_if.c\
		parse_ip.c\
		parse_ip_opts.c\
		parse_mtu.c\
		parse_os_detection_tries.c\
		parse_port.c\
		parse_scan.c\
		parse_scanflags.c\
		parse_speedup.c\
		parse_spoofed_src_ip.c\
		parse_spoofed_src_mac.c\
		parse_spoofed_src_port.c\
		parse_ttl.c\
	)\
)
