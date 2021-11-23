
# include <ft_types.h>
# include <ft_error.h>

# include <arpa/inet.h>

void dbg_parse_opts(args_t* const args)
{
    DEBUG("PARSE OPTS:\n* FILE: %p\n* NB THREADS: %hu\n* OS MAX TRIES: %hhu\n* MTU: %lu\n* SRC IP: %s\n* IF: %s\n* SRC PORT: %hu\n* DATA: %s\n* IP OPTS: %s\n* TTL: %hhu\n* SRC MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n* DECOYS: %s\n\n",
    args->file, args->nb_threads, args->os_det_tries, args->mtu, inet_ntoa((struct in_addr){args->scr_ip}), args->interface, args->scr_port, args->data, args->ip_opts, args->ttl,
    args->src_mac[0], args->src_mac[1], args->src_mac[2], args->src_mac[3], args->src_mac[4], args->src_mac[5], args->decoys);
}
