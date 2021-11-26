
# pragma once

# include <ft_packet_crafting.h>

# include <netdb.h>

typedef struct	routine_data
{
	u8**			pks_data;
	u64*			pks_len;
	struct sockaddr host;
	u64				opts;
	u8				os_det_tries;
	u64				mtu;
	const u8*		decoys;
}				routine_data_t;

err_t getsockfromif(struct sockaddr* const res, const char* ifname);

routine_data_t*	gen_routine_data(const packets_t* const packets,
				const struct sockaddr* const host, const parse_t* const parse, portpref_t preffix);
void			free_routine_data(routine_data_t* data);

err_t	process_host_port(void* data);
err_t   process_host(parse_t* const parse, const struct sockaddr* const host,
		const packets_t* const packets);
err_t	process_all_hosts(parse_t* const parse, const packets_t* const packets);
