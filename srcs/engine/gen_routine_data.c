
# include <ft_engine.h>
# include <ft_utils.h>

# include <stdlib.h>
# include <string.h>

static u8*  gen_new_array_elem(const packet_t* const pk, u64* const pklen)
{
    u8* buff = malloc(sizeof(u8) * pk->pk_bytes);
    if (buff)
    {
        memcpy(buff,pk->pk_data, pk->pk_bytes);
        *pklen = pk->pk_bytes;
    }
    return buff;
}

__attribute__ ((always_inline))
static inline u64 calc_arr_len(const parse_t* const parse, portpref_t preffix)
{
    return (bool)(BITHAS(parse->opts, O_S_TCPSYN) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPACK) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPWIN) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPMAI) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_UDP) || preffix == PREF_UDP)
    + (bool)(BITHAS(parse->opts, O_S_TCPNUL) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPFIN) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPXMA) || preffix == PREF_TCP)
    + (bool)(BITHAS(parse->opts, O_S_TCPCUS))
    + (bool)(BITHAS(parse->opts, O_S_SCTPIN) || preffix == PREF_SCTP)
    + (bool)(BITHAS(parse->opts, O_S_SCTPCE) || preffix == PREF_SCTP)
    + (bool)(BITHAS(parse->opts, O_S_IPPROT));
}

static u8**     gen_packets_array(const packets_t* const packets, u64** const packets_len,
const parse_t* const parse, portpref_t preffix)
{
    u8** arr;
    u64* lens;

    {
        const u64 arrlen = calc_arr_len(parse, preffix);

        arr = malloc(sizeof(u8*) * (arrlen + 1));
        if (arr == NULL)
            return NULL;

        lens = malloc(sizeof(u64) * (arrlen));
        if (lens == NULL)
        {
            free(arr);
            return NULL;
        }
    }

    register u64 i = 0;

    if (BITHAS(parse->opts, O_S_TCPSYN) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_syc, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPACK) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_ack, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPWIN) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_win, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPMAI) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_maimon, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_UDP) || preffix == PREF_UDP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->udp, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPNUL) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_nul, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPFIN) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_fin, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPXMA) || preffix == PREF_TCP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_xmas, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_TCPCUS))
    {
        if ((arr[i] = gen_new_array_elem(&packets->tcp_custom, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_SCTPIN) || preffix == PREF_SCTP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->sctp_init, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_SCTPCE) || preffix == PREF_SCTP)
    {
        if ((arr[i] = gen_new_array_elem(&packets->sctp_cookie_echo, &lens[i++])) == NULL)
            goto error;
    }
    if (BITHAS(parse->opts, O_S_IPPROT))
    {
        if ((arr[i] = gen_new_array_elem(&packets->ipproto, &lens[i++])) == NULL)
            goto error;
    }

    *packets_len = lens;
    return arr;

error:
    for (u8** it = arr ; *it ; it++)
        free(*it);
    free(arr);
    free(lens);
    return NULL;
}

routine_data_t*	gen_routine_data(const packets_t* const packets,
const struct sockaddr* const host, const parse_t* const parse, portpref_t preffix)
{
    routine_data_t* const data = malloc(sizeof(routine_data_t));

    if (data)
    {
        u64* pks_len;
        u8** const pks = gen_packets_array(packets, &pks_len, parse, preffix);

        if (pks == NULL)
        {
            free(data);
            return NULL;
        }

        *data = (routine_data_t){
            .pks_data = pks,
            .pks_len = pks_len,
            .host = *host,
            .opts = parse->opts,
            .os_det_tries = parse->args.os_det_tries,
            .mtu = parse->args.mtu,
            .decoys = parse->args.decoys
        };
    }

    return data;
}
