
# include <ft_engine.h>
# include <ft_parse.h>

err_t	process_all_hosts(parse_t* const parse, const packets_t* const packets)
{
    err_t st = SUCCESS;

    do
    {
        ///TODO: Host processing order can be randomized
        for (register u32* ip = parse->args.ips ; *ip ; ip++)
        {
            ///TODO: Get sockaddr ( use getifaddrs, always ? )
            struct sockaddr* saddr;(void)ip;

            if ((st = process_host(parse, saddr, packets)) != SUCCESS)
                goto error;
        }
    }
    while (
        parse->args.no_ip_iterations == false
        && (st = parse_ips_iteration(parse->args.av_ip, parse->args.totalips, parse)) == SUCCESS
    );

error:
    return st == BREAK ? SUCCESS : st;
}
