
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>
# include <errno.h>
# include <arpa/inet.h>

# include <string.h>

__attribute__ ((always_inline))
static inline u64 get_sep_index(char* s, u32 sep)
{
	u64 sep_index = 0;
	while (s[sep_index] != sep)
		sep_index++;
	return sep_index;
}


static bool check_range_format(char* valueptr)
{
	u32 count = 0;

	/// TODO: MUST BE TRUE FOR SUBNETS

	if (ISNUM(*valueptr))
	{
		for ( ; *valueptr ; valueptr++)
		{
			if (!ISNUM(*valueptr))
			{
				if (*valueptr == '-' && *(valueptr + 1))
				{
					count++;
					continue ;
				}
				return false;
			}
		}
	}
	return count == 1;
}

static bool is_range_format(char* valueptr)
{
	///TODO: MUST BE TRUE FOR SUBNETS

	for (u64 i = 0 ; valueptr[i] ; i++)
		if (valueptr[i] == '-')
			return true;
	return false;
}

static bool check_unique_format(char* valueptr)
{
	for ( ; *valueptr ; valueptr++)
		if (!ISNUM(*valueptr))
			return false;
	return true;
}

static bool check_dns_format(char* valueptr)
{
	///TODO: Try to resolve dns

	return false;
}

static u32 get_unique(char* unique)
{
	return atoi(unique);
}

static u32 get_first_in_range(char* range)
{
	char buff[0X10] = {0};
	memcpy(buff, range, get_sep_index(range, '-'));
	return atoi(buff);
}

static u32 get_last_in_range(char* range)
{
	char buff[0X10] = {0};
	const u64 sep_index = get_sep_index(range, '-');
	memcpy(buff, range + sep_index + 1, strlen(&range[sep_index + 1]));
	return atoi(buff);
}

static u32 get_ip_unique(char* valueptr)
{
	return inet_addr(valueptr);
}

static err_t get_first_ip_range(char* valueptr, u32* const val)
{
	///TODO: CAN BE A SUBNET

	i16 firsts[4] = {-1, -1, -1, -1};
	u8 res[4] = {0};
	char** bytes = split(valueptr, '.');
	if (bytes == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for (u64 i = 0 ; i < ARRAYSIZE(firsts) ; i++)
	{
		if (is_range_format(bytes[i]))
			firsts[i] = (i16)get_first_in_range(bytes[i]);
	}

	///TODO: Modify firsts by the subnet if there are

	for (u64 i = 0 ; i < ARRAYSIZE(res) ; i++)
	{
		if (firsts[i] == -1)
			res[i] = get_unique(bytes[i]) & 0XFF;
		else
			res[i] = (u8)firsts[i];
	}

	*val = *(u32*)res;

	free_split(bytes);
	return SUCCESS;
}

static err_t get_next_ip(char** valueptr, u32* const next_ip)
{
	if (*(++valueptr) == NULL)
		*next_ip = 0;
	else if (is_range_format(*valueptr))
	{
		if (get_first_ip_range(*valueptr, next_ip) != SUCCESS)
			return ESYSCALL;
	}
	else
		*next_ip = get_ip_unique(*valueptr);

	return SUCCESS;
}

static err_t validate_ip_format(char* ip, u64* const lenght)
{
	err_t	st = SUCCESS;

	char**	bytes = split(ip, '.');
	u32		total_length[4] = {0};

	if (bytes == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	if (bytes[1] == NULL || bytes[2] == NULL || bytes[3] == NULL || *(bytes[3]) == 0 || bytes[4])
	{
		st = EARGUMENT;
		goto error;
	}

	u16 has_zero = 0;

	for (size_t i = 0 ; i < 4 ; i++)
	{
		///TODO: ADD SUBNET
		if (check_range_format(bytes[i]))
		{
			const u32 first = get_first_in_range(bytes[i]);
			if (first > 0XFF)
				goto error;

			const u32 last = get_last_in_range(bytes[i]);
			if (last > 0XFF)
				goto error;

			if (first == 0 || last == 0)
				has_zero++;

			if ((i32)(last - first) <= 0)
				goto error;

			total_length[i] = last - first + 1;
		}
		else if (check_unique_format(bytes[i]))
		{
			const u16 value = get_unique(bytes[i]);
			if (value > 0XFF)
				goto error;
			if (value == 0)
				has_zero++;

			total_length[i] = 1;
		}
		else
			goto check_dns;

		if (has_zero == 4)
		{
			PRINT_ERROR(EMSG_ZEROED_IP, O_IP_STR);
			goto error;
		}
	}

	if (0 /* SUBNET */)
	{
		// Change in total_lenght the ranges affected by the subnet
	}

	*lenght += total_length[0] * total_length[1] * total_length[2] * total_length[3];
	free_split(bytes);
	return SUCCESS;

check_dns:
	if (check_dns_format(ip) == true)
		*lenght = 1;
error:
	free_split(bytes);
	return EARGUMENT;
}

static char** find_ip(char** values, u32 tofind)
{
	if (tofind == 0)
		return values;

	u8 tofind_bytes[4] = {
		((tofind & 0X000000FF)) & 0XFF,
		((tofind & 0X0000FF00) >> 8) & 0XFF,
		((tofind & 0X00FF0000) >> 16) & 0XFF,
		((tofind & 0XFF000000) >> 24) & 0XFF
	};

	for ( ; *values ; values++)
	{
		///TODO: And not a DNS
		if (is_range_format(*values))
		{
			///TODO: Handle subnet

			char** bytes = split(*values, '.');

			if (bytes == NULL)
			{
				PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
				return NULL;
			}

			u8 matches = 0;
			for (u64 i = 0 ; i < ARRAYSIZE(tofind_bytes) ; i++)
			{
				if (is_range_format(bytes[i]))
				{
					const u8 first = get_first_in_range(bytes[i]);
					const u8 last = get_last_in_range(bytes[i]);

					DEBUG("FIRST %hhu LAST %hhu X %hhu\n", first, last, tofind_bytes[i]);
					matches += (bool)ISVAL_INRANGE(tofind_bytes[i], first, last);
				}
				else
					matches += (bool)(tofind_bytes[i] == get_unique(bytes[i]));
				DEBUG("MATCHES %hhu\n", matches);
			}

			free_split(bytes);

			if (matches == 4)
				return values;
		}
		else
		{
			if (get_ip_unique(*values) == tofind)
				return values;
		}
	}

	return NULL;
}


static u64 calc_max_possible(u8* const first, u8* const last)
{
	u64 exp[4] = {1, 1, 1, 1};

	for (u64 i = 0 ; i < ARRAYSIZE(exp) ; i++)
	{
		if (last[i])
			exp[i] = last[i] - first[i] + 1;
	}

	return exp[0] * exp[1] * exp[2] * exp[3];
}

static err_t is_last_iteration(u32 curr, const char* s, bool* const is_last)
{
	err_t	st = SUCCESS;
	char**	values = split((char*)s, ',');
	char**	base = values;
	u64		lenght = 0;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	DEBUG("curr is %u\n", curr);

	u8 firsts[4] = {
		((curr & 0X000000FF)) & 0XFF,
		((curr & 0X0000FF00) >> 8) & 0XFF,
		((curr & 0X00FF0000) >> 16) & 0XFF,
		((curr & 0XFF000000) >> 24) & 0XFF
	};
	u8	lasts[4] = {0};

	char**	valuesprt = find_ip(values, curr);
	if (valuesprt == NULL)
	{
		st = ESYSCALL;
		goto end;
	}

	for ( ; *valuesprt ; valuesprt++)
	{
		/// TODO: And not a DNS
		if (is_range_format(*valuesprt))
		{
			///TODO: Handle subnet

			char**	bytes = split(*values, '.');

			if (bytes == NULL)
			{
				PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
				st = ESYSCALL;
				goto end;
			}

			memset(lasts, 0, ARRAYSIZE(lasts));

			///TODO: LAST VALUES DEPEND ON THE SUFIIX (SUBNET)
			for (u64 i = 0 ; i < ARRAYSIZE(lasts) ; i++)
			{
				if (is_range_format(bytes[i]))
					lasts[i] = get_last_in_range(bytes[i]);
			}

			lenght += calc_max_possible(firsts, lasts);

			DEBUG("LENGHT %lu\n", lenght);

			free_split(bytes);
		}
		else
			lenght++;
		
		if (lenght >= IP_ITERATION_NB)
		{
			*is_last = false;
			goto end;
		}
	}
	DEBUG("lenght is %lu\n",lenght);
	*is_last = true;
end:
	free_split(base);
	return st;
}

static err_t count_ips(u64* const ip_nb, const char* s)
{
	err_t 	st = SUCCESS;
	char**	values = split((char*)s, ',');
	char**	base = values;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for ( ; *values ; values++)
	{
		if (!**values)
		{
			st = EARGUMENT;
			break ;
		}
		if ((st = validate_ip_format(*values, ip_nb)) != SUCCESS)
			break ;
	}

	if (st == EARGUMENT)
		PRINT_ERROR(EMSG_INVARG, O_IP_STR, s);

	free_split(base);
	return st;
}

static err_t copy_range_ip(char* ip, const parse_t* parse, u64 max_allowed, u64* const buffindex, u32* const next)
{
	err_t	st = SUCCESS;
	u64		cplen = 0;
	char**	bytes = split(ip, '.');
	if (bytes == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		st = ESYSCALL;
		return ESYSCALL;
	}

	u8	lasts[4] = {0};

	///TODO: LAST VALUES DEPEND ON THE SUFIIX (SUBNET)
	for (u64 i = 0 ; i < ARRAYSIZE(lasts) ; i++)
	{
		if (is_range_format(bytes[i]))
			lasts[i] = get_last_in_range(bytes[i]);
	}

	const u32 curr = parse->args.currip;

	u8 firsts[4] = {
		((curr & 0X000000FF)) & 0XFF,
		((curr & 0X0000FF00) >> 8) & 0XFF,
		((curr & 0X00FF0000) >> 16) & 0XFF,
		((curr & 0XFF000000) >> 24) & 0XFF
	};

	const u64 max_possible = calc_max_possible(firsts, lasts);

	for (u16 fourth = firsts[0] ; fourth <= lasts[0] || lasts[0] == 0 ; )
	{
		for (u16 third = firsts[1] ; third <= lasts[1] || lasts[1] == 0 ; )
		{
			for (u16 second = firsts[2] ; second <= lasts[2] || lasts[2] == 0 ; )
			{
				for (u16 first = firsts[3] ; first <= lasts[3] || lasts[3] == 0 ; )
				{
					u8* conversion = (u8*)&parse->args.ips[(*buffindex)++];
					conversion[0] = fourth;
					conversion[1] = third;
					conversion[2] = second;
					conversion[3] = first;

					if (++cplen == max_possible)
						goto end;

					/*	Last elem in buff is always 0,
						here i write the value at end + 1
						in the last elem of buff,
						then i store it and set it to 0 again */
					if (cplen == max_allowed + 1)
					{
						*next = parse->args.ips[--(*buffindex)];
						parse->args.ips[(*buffindex)--] = 0;
						goto end;
					}

					if (lasts[3])
						first++;
					else
						break ;
				}

				if (lasts[2])
					second++;
				else
					break ;
			}

			if (lasts[1])
				third++;
			else
				break ;
		}

		if (lasts[0])
			fourth++;

	}

end:
	free_split(bytes);
	return SUCCESS;
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
	if (valueptr == NULL)
	{
		st = ESYSCALL;
		goto error;
	}

	if (parse->args.currip == 0)
	{
		if (is_range_format(*valueptr)) // AND NOT DNS
		{
			if ((st = get_first_ip_range(*valueptr, &parse->args.currip)) != SUCCESS)
				goto error;
		}
		else
			parse->args.currip = get_ip_unique(*valueptr);
	}

	u32 next_iteration_start;
	u64 buffindex = 0;
	while (*valueptr && cplen < bufflen)
	{
		///TODO: AND NOT A DNS
		if (is_range_format(*valueptr))
		{
			u32 next = 0;
			u64 prev_buffindex = buffindex;
			if ((st = copy_range_ip(*valueptr, parse, bufflen, &buffindex, &next)) != SUCCESS)
				goto error;

			cplen += buffindex - prev_buffindex + 1;

			DEBUG("CPLEN IS %lu\n", cplen);
			if (cplen == bufflen)
			{
				DEBUG("NEXT ----> %u\n", next);
				if (next)
					next_iteration_start = next;
				else
				{
					if ((st = get_next_ip(valueptr, &next_iteration_start)) != SUCCESS)
						goto error;

					DEBUG("next it %u\n", next_iteration_start);
				}
			}
		}
		else
		{
			parse->args.ips[buffindex++] = get_ip_unique(*valueptr);
			cplen++;

			if (cplen == bufflen)
			{
				if ((st = get_next_ip(valueptr, &next_iteration_start)) != SUCCESS)
					goto error;
			}
		}
		valueptr++;
		if (*valueptr && is_range_format(*valueptr)) /// AND NOT DNS
		{
			if ((st = get_first_ip_range(*valueptr, &parse->args.currip)) != SUCCESS)
				goto error;
		}
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

	DEBUG("*** NEW IT (curr is: %u (%s))\n", parse->args.currip, inet_ntoa((struct in_addr){parse->args.currip}));

	DEBUG("is last : %d\n", is_last_ip);

	const u64 bufflen = is_last_ip ? ip_nb % IP_ITERATION_NB : MIN(ip_nb, IP_ITERATION_NB);

	if (parse->args.ips == NULL)
	{
		if ((parse->args.ips = malloc(sizeof(*parse->args.ips) * (bufflen + 1))) == NULL)
		{
			PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
			st = ESYSCALL;
			goto error;
		}
	}
	else
		memset(parse->args.ips, 0, IP_ITERATION_NB);

	DEBUG("BUFFLEN --> %lu\n", bufflen);

	if ((st = copy_ips(parse, bufflen, s)) != SUCCESS)
		goto error;

	DEBUG("%s\n", "HERE -->");

	memset(parse->args.ips + bufflen, 0, sizeof(*parse->args.ips));

	st =  is_last_ip ? BREAK : SUCCESS;

	DEBUG("CURR IP IS %u\n", parse->args.currip);

error:
	DEBUG("RET %d\n", st);
	return st;
}

///TODO: TRANSITION RANGE/UNIQUE TO RANGE IN MULTIPLE IPS RANGES (FOR MULTIPLE ITERATIONS)

///TODO: Subnet
///TODO: DNS
///TODO: Repated ips

err_t	parse_ips(const char* s, parse_t* const parse)
{
	err_t st = SUCCESS;
	u64 ip_nb = 0;

	if ((st = count_ips(&ip_nb, s)) != SUCCESS)
		goto error;

	// char* repeated;
	// if ((st = check_repeated_ip(s, repeated)) != SUCCESS)
	// {
	// 	PRINT_ERROR(EMSG_REPEATED_IP, repeated);
	// 	st = EARGUMENT;
	// 	goto error;
	// }

	DEBUG("TOTAL IPS: %lu\n", ip_nb);

	parse->args.totalips = ip_nb;

	st = parse_ips_iteration(s, ip_nb, parse);

error:
	return st;
}
