
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>
# include <errno.h>

# include <string.h>

static const** find_ip(char** values, u16 tofind)
{
	
}

static err_t is_last_iteration(u16 curr, const char* s, bool* const is_last)
{
	///TODO: When i fix how to handle uncontinious ip ranges ( eg: 11.1-15.13.14 )

	return SUCCESS;
}

static err_t count_ips(u64* const ip_nb, const char* s)
{
	err_t 	st = SUCCESS;
	u64		total = 0;
	char**	values = split((char*)s, ',');
	char**	base = values;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for ( ; *values ; values++)
	{
		if (check_range_format(*values)) // TODO: Validate inside ranges / netmask & ZEROED IP
		{
			const u64 first = get_first_ip_range(*values);
			const u64 last = get_last_ip_range(*values, first, 0, 0);

			///TODO: WRONG! NOT ALL IP RANGES ARE CONTINUOUS
			total += last - first + 1;
		}
		else if (check_unique_format(*values)) // Also TODO
			total++;
		else
			goto error;
	}
	*ip_nb = total;
	free_split(base);
	return st;

error:
	free_split(base);
	PRINT_ERROR(EMSG_INVARG, O_IP_STR, s);
	return EARGUMENT;
}

static err_t copy_ips(parse_t* const parse,  u64 bufflen, const char* s)
{
	err_t	st = SUCCESS;
	u64		cplen = 0;
	char**	valueptr;
	char**	values = split((char*)s, ',');

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		st = ESYSCALL;
		goto error;
	}

	valueptr = find_ip(values, parse->args.currip);

	if (parse->args.currip == 0)
	{
		if (is_range_format(*valueptr))
			parse->args.currip = get_first_ip_range(*valueptr);
		else
			parse->args.currip = get_ip_unique(*valueptr);
	}

	u32 next_iteration_start;
	u64 buffindex = 0;
	while (*valueptr && cplen < bufflen)
	{
		if (is_range_format(*valueptr))
		{
			bool is_last = false;
			const u64 lastinrange = get_last_ip_range(*valueptr, parse->args.currip, bufflen - cplen, &is_last);

			///TODO: WRONG! NOT ALL IP RANGES ARE CONTINUOUS
			for (u64 value = parse->args.currip ; value <= lastinrange ; value++)
				parse->args.ips[buffindex++] = value;
			
			///TODO: WRONG! NOT ALL IP RANGES ARE CONTINUOUS
			cplen += lastinrange - parse->args.currip + 1;

			///TODO: WRONG! NOT ALL IP RANGES ARE CONTINUOUS
			if (cplen == bufflen)
				next_iteration_start = is_last ? get_next_ip(valueptr) : lastinrange + 1;
		}
		else
		{
			parse->args.ips[buffindex++] = get_ip_unique(*valueptr);
			cplen++;

			if (cplen == bufflen)
				next_iteration_start = get_next_ip(valueptr);
		}
		valueptr++;
		if (*valueptr && is_range_format(*valueptr))
			parse->args.currip = get_first_ip_range(*valueptr);
	}
	parse->args.currip = next_iteration_start;

error:
	free_split(values);
	return st;
}

err_t	parse_ips_iteration(const char* s, u64 ip_nb, parse_t* const parse)
{
	err_t	st = SUCCESS;
	bool	is_last_ip = false;

	if ((st = is_last_iteration(parse->args.currport, s, &is_last_ip)) != SUCCESS)
		goto error;

	const u64 bufflen = is_last_ip ? ip_nb % IP_ITERATION_NB : MIN(ip_nb, IP_ITERATION_NB);

	if (parse->args.ips == NULL)
	{
		if ((parse->args.ports = malloc(sizeof(*parse->args.ips) * (bufflen + 1))) == NULL)
		{
			PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
			st = ESYSCALL;
			goto error;
		}
	}
	else
		memset(parse->args.ips, 0, IP_ITERATION_NB);

	if ((st = copy_ips(parse, bufflen, s)) != SUCCESS)
		goto error;

	memset(parse->args.ips + bufflen, 0, sizeof(*parse->args.ips));

	st =  is_last_ip ? BREAK : SUCCESS;

error:
	return st;
}

err_t	parse_ip(const char* s, parse_t* const parse)
{
	err_t st = SUCCESS;
	u64 ip_nb = 0;

	if ((st = count_ips(&ip_nb, s)) != SUCCESS)
		goto error;

	char* repeated;
	if ((st = check_repeated_ip(s, repeated)) != SUCCESS)
	{
		PRINT_ERROR(EMSG_REPEATED_IP, repeated);
		st = EARGUMENT;
		goto error;
	}

	parse->args.totalips = ip_nb;

	st = parse_ips_iteration(s, ip_nb, parse);

error:
	return st;
}