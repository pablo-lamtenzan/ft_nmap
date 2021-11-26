
# include <ft_engine.h>
# include <ft_parse.h>
# include <ft_utils.h>

# include <stdlib.h>

static err_t process_all_hosts_randomly(parse_t* const parse, const packets_t* const packets)
{
	err_t st = SUCCESS;

	register u64 lenght = 0;
	for ( ; parse->args.ips[lenght] != 0 ; lenght++);

	register u64 i = 0;
	register u32 dest;
	u8 lenreach_times = 0;

	do
	{
		for ( ; ; )
		{
			i = rand() % lenght;

			if (parse->args.ips[i] != 0)
				dest = parse->args.ips[i];
			else
			{
				lenreach_times = 0;
				while (parse->args.ips[i] == 0)
				{
					if (i == lenght)
					{
						i = -1;
						if (++lenreach_times > 1)
							goto error;
					}
					i++;
				}
			}

			///TODO: Get sockaddr ( use getifaddrs, always ? )
			///TODO: Whether i use an if i have to use ETH packets in other cases only ip ones
			struct sockadddr* saddr;(void)dest;

			parse->args.ips[i] = 0;

			if ((st = process_host(parse, saddr, packets)) != SUCCESS)
				goto error;
		}
	}
	while (
		parse->args.no_ip_iterations == false
		&& (st = parse_ips_iteration(parse->args.av_ip, parse->args.totalips, parse)) == SUCCESS
	);

error:
	return st;
}

static err_t process_all_host_sequentialy(parse_t* const parse, const packets_t* const packets)
{
	err_t st = SUCCESS;

	do
	{
		for (register u32* ip = parse->args.ips ; *ip ; ip++)
		{
			///TODO: Get sockaddr ( use getifaddrs, always ? )
			///TODO: Whether i use an if i have to use ETH packets in other cases only ip ones
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
	return st;
}

err_t	process_all_hosts(parse_t* const parse, const packets_t* const packets)
{
    err_t st = SUCCESS;

    if (BITHAS(parse->opts, O_EV_RHST))
		st = process_all_hosts_randomly(parse, packets);
    else
		st = process_all_host_sequentialy(parse, packets);

error:
    return st == BREAK ? SUCCESS : st;
}
