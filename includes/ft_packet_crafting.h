
# pragma once

# include <ft_error.h>
# include <ft_types.h>

typedef struct	packet
{
	u8*	pk_data;
	u64	pk_bytes;
}				packet_t;

typedef struct	packets
{
	packet_t	tcp_syc;
	packet_t	tcp_ack;
	packet_t	tcp_win;
	packet_t	tcp_maimon;
	packet_t	udp;
	packet_t	tcp_nul;
	packet_t	tcp_fin;
	packet_t	tcp_xmas;
	packet_t	tcp_custom;
	packet_t	sctp_init;
	packet_t	sctp_cookie_echo;
	packet_t	ipproto;
}				packets_t;

err_t	pk_crafter(packets_t* const res, parse_t* const parse);

err_t	pk_craft_tcp_syc(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_ack(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_win(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_maimon(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_udp(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_nul(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_fin(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_xmas(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_tcp_custom(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_scpt_init(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_scpt_cookie_echo(packet_t* const pk_res, parse_t* const parse);
err_t	pk_craft_ipproto(packet_t* const pk_res, parse_t* const parse);

void	free_pk_craft(packets_t* const packets);
