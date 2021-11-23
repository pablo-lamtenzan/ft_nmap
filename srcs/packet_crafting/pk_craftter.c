
# include <ft_packet_crafting.h>

err_t pk_craft(packets_t* const res, parse_t* const parse)
{
    err_t st = SUCCESS;

    if ((st = pk_craft_tcp_syc(&res->tcp_syc, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_ack(&res->tcp_ack, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_win(&res->tcp_win, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_maimon(&res->tcp_maimon, parse)) != SUCCESS
    ||  (st = pk_craft_udp(&res->udp, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_nul(&res->tcp_nul, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_fin(&res->tcp_fin, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_xmas(&res->tcp_xmas, parse)) != SUCCESS
    ||  (st = pk_craft_tcp_custom(&res->tcp_custom, parse)) != SUCCESS
    ||  (st = pk_craft_scpt_init(&res->sctp_init, parse)) != SUCCESS
    ||  (st = pk_craft_scpt_cookie_echo(&res->sctp_cookie_echo, parse)) != SUCCESS
    ||  (st = pk_craft_ipproto(&res->ipproto, parse)) != SUCCESS)
        goto error;

error:
    return st;
}

