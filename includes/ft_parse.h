
# pragma once

# include <ft_types.h>

# define O_HELP_STR "--help"
# define O_FULLPORT_STR "--port-max=unlimited"
# define O_PORT_STR "--ports"
# define O_IP_STR "--ip"
# define O_FILE_STR "--file"
# define O_SPEEDUP_STR "--speedup"

# define O_SCAN_STR "--scan"
# define O_S_TCPSYN_STR "-sS"
# define O_S_TCPCON_STR "-sT"
# define O_S_TCPACK_STR "-sA"
# define O_S_TCPWIN_STR "-sW"
# define O_S_TCPMAI_STR "-sU"
# define O_S_UDP_STR "-sU"
# define O_S_TCPNUL_STR "-sN"
# define O_S_TCPFIN_STR "-sF"
# define O_S_TCPXMA_STR "-sX"
# define O_S_TCPCUS_STR "--scanflags"
# define O_S_SCTPIN_STR "-sY"
# define O_S_SCTPCE_STR "-sZ"
# define O_S_IPPROT_STR "-sO"

# define O_VE_UP_STR "-sV"
# define O_VE_LIGHT_STR "--version-light"
# define O_VE_ALL_STR "--version-all"

# define O_OS_UP_STR "-O"
# define O_OS_LIM_STR "--osscan-limit"
# define O_OS_GSS_STR "--osscan-guess"
# define O_OS_MTR_STR "--max-os-tries"

# define O_EV_MTU_STR "--mtu"
# define O_EV_FRG_STR "-f"
# define O_EV_DEC_STR "-D"
# define O_EV_IP_STR "-S"
# define O_EV_IF_STR "-e"
# define O_EV_SPRT_STR "-g"
# define O_EV_HDAT_STR "--data-hex"
# define O_EV_SDAT_STR "--data-string"
# define O_EV_RDAT_STR "--data-lenght"
# define O_EV_IPOP_STR "--ip-options"
# define O_EV_TTL_STR "--ttl"
# define O_EV_RHST_STR "--randomize-hosts"
# define O_EV_MAC_STR "--spoof-mac"
# define O_EV_BSUM "--badsum"

typedef err_t (*const parse_arg_t)(const char**, parse_t* const);

err_t   parse_all_arguments(const char** av[], parse_t* const parse);
void    free_parse(parse_t* const parse);
err_t	parse_ports(const char** s, parse_t* const parse);
err_t	parse_ports_iteration(const char* s, u64 port_nb, parse_t* const parse);
err_t	parse_ips(const char** s, parse_t* const parse);
err_t	parse_ips_iteration(const char* s, u64 ip_nb, parse_t* const parse);
err_t   parse_data_hex(const char** s, parse_t* const parse);
err_t   parse_data_lenght(const char** s, parse_t* const parse);
err_t   parse_data_string(const char** s, parse_t* const parse);
err_t   parse_decoy(const char** s, parse_t* const parse);
err_t   parse_file(const char** s, parse_t* const parse);
err_t   parse_if(const char** s, parse_t* const parse);
err_t   parse_ip_opts(const char** s, parse_t* const parse);
err_t   parse_mtu(const char** s, parse_t* const parse);
err_t   parse_os_detection_tries(const char** s, parse_t* const parse);
err_t   parse_scan(const char** s, parse_t* const parse);
err_t   parse_scanflags(const char** s, parse_t* const parse);
err_t   parse_speedup(const char** s, parse_t* const parse);
err_t   parse_spoofed_src_ip(const char** s, parse_t* const parse);
err_t   parse_spoofed_src_mac(const char** s, parse_t* const parse);
err_t   parse_spoofed_src_port(const char** s, parse_t* const parse);
err_t   parse_ttl(const char** s, parse_t* const parse);
