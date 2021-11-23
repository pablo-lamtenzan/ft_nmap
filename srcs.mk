INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	debug.h\
	ft_engine.h\
	ft_error.h\
	ft_libc.h\
	ft_nmap.h\
	ft_packet_crafting.h\
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
		free_routine_data.c\
		gen_routine_data.c\
		process_all_hosts.c\
		process_host.c\
		process_host_port.c\
	)\
	$(addprefix ft_libc/,\
		ft_strtol.c\
		split.c\
	)\
	main.c\
	$(addprefix packet_crafting/,\
		free_pk_craft.c\
		pk_craftipproto.c\
		pk_craftscpt_cookie_echo.c\
		pk_craftscpt_init.c\
		pk_craft_tcp_ack.c\
		pk_crafttcp_custom.c\
		pk_crafttcp_fin.c\
		pk_craft_tcp_maimin.c\
		pk_craft_tcp_syn.c\
		pk_craft_tcp_win.c\
		pk_crafttcp_xmas.c\
		pk_craftter.c\
		pk_craft_tmp_nul.c\
		pk_craft_udp.c\
	)\
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
