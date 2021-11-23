
# include <ft_packet_crafting.h>

# include <stdlib.h>

void    free_pk_craft(packets_t* const packets)
{
    free(packets->tcp_syc.pk_data);
    free(packets->tcp_ack.pk_data);
    free(packets->tcp_win.pk_data);
    free(packets->tcp_maimon.pk_data);
    free(packets->udp.pk_data);
    free(packets->tcp_nul.pk_data);
    free(packets->tcp_fin.pk_data);
    free(packets->tcp_xmas.pk_data);
    free(packets->tcp_custom.pk_data);
    free(packets->sctp_init.pk_data);
    free(packets->sctp_cookie_echo.pk_data);
    free(packets->ipproto.pk_data);
}
