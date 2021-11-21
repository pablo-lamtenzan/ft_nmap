
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>
# include <errno.h>

# include <string.h>

/* Exec hots/port random in array

arg: index (random value between 0 and size)

if (arr[index] not 0)
	: use value at index
else
	: iterate forward
		if (arr[index] < size && arr[index] not 0)
			: value at index
		else
			: go to the begin and iterate until arr[index] not 0

size-- // size decreases at the end

END
*/

__attribute__ ((always_inline))
static inline u64 get_sep_index(char* range, u32 sep)
{
	u64 sep_index = 0;
	while (range[sep_index] != sep)
		sep_index++;
	return sep_index;
}

/// @brief Parses preffix and increment value if the format is valid
/// Otherwise, other function will throw error cause prefix is not an
/// unique / ranged port format
static portpref_t skip_preffix(char** valueptr)
{
	portpref_t preffix = PREF_NONE;

	if ((*valueptr)[1] == ':')
	{
		switch (**valueptr)
		{
			case 'T':
				preffix = PREF_TCP;
				break ;
			case 'U':
				preffix = PREF_UDP;
				break ;
			case 'S':
				preffix = PREF_SCTP;
				break ;
			default:
				preffix = PREF_ERROR;
		}
		if (valueptr != PREF_NONE)
			*valueptr += 2;
	}

	return preffix;
}

/// @brief Get numerical value from string @a valueptr following unique port format
static u32	get_port_unique(char* valueptr, portpref_t* const preffix)
{
	const portpref_t pref = skip_preffix(&valueptr);

	if (preffix)
		*preffix = pref;

	return atoi(valueptr);
}

/// @brief Get numerical first range value from string @a valueptr following ranged port format
static u32	get_first_port_range(char* valueptr, portpref_t* const preffix)
{
	const portpref_t pref = skip_preffix(&valueptr);

	if (preffix)
		*preffix = pref;

	char buff[0X10] = {0};
	memcpy(buff, valueptr, get_sep_index(valueptr, '-'));
	return atoi(buff);
}

/// @brief Get numerical last range value from string @a valueptr following ranged port format
static u32	get_last_port_range(char* valueptr, u16 start, u64 max, bool* const is_last, portpref_t* const preffix)
{
	const portpref_t pref = skip_preffix(&valueptr);

	if (preffix)
		*preffix = pref;

	char buff[0X10] = {0};

	const u64 sep_index = get_sep_index(valueptr, '-');
	memcpy(buff, valueptr + sep_index + 1, strlen(&valueptr[sep_index + 1]));

	u32 value = atoi(buff);

	if (is_last)
	{
		if (value >= start + max)
			value = start + max - 1;
		else
			*is_last = true;
	}

	return value;
}

static bool	has_range_in_range(char* target, char* range, u16* const repeated)
{
	const u32 target_first = get_first_port_range(target, 0);
	const u32 target_last = get_last_port_range(target, target_first, 0, 0, 0);
	const u32 range_first = get_first_port_range(range, 0);
	const u32 range_last = get_last_port_range(range, range_first, 0, 0, 0);

	*repeated = 0;

	if (target_first >= range_first && target_first <= range_last)
		*repeated = target_first;
	if (target_last >= target_first && target_last <= range_last)
		*repeated = target_last;

	return *repeated != 0;
}

static bool has_unique_in_range(char* target, char* unique, u16* const repeated)
{
	const u32 target_first = get_first_port_range(target, 0);
	const u32 target_last = get_last_port_range(target, target_first, 0, 0, 0);
	const u32 unique_value = get_port_unique(unique, 0);

	*repeated = 0;

	if (unique_value >= target_first && unique_value <= target_last)
		*repeated = unique_value;
	
	return *repeated != 0;
}

static bool check_range_format(char* valueptr)
{
	u32 count = 0;

	skip_preffix(&valueptr);

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

/// @brief Return true if @a valueptr follow ranged port format
static bool is_range_format(char* valueptr)
{
	skip_preffix(&valueptr);

	for (u64 i = 0 ; valueptr[i] ; i++)
		if (valueptr[i] == '-')
			return true;
	return false;
}

/// @brief Return true if @a valueptr follow unique port format
static bool check_unique_format(char* valueptr)
{
	skip_preffix(&valueptr);

	for ( ; *valueptr ; valueptr++)
		if (!ISNUM(*valueptr))
			return false;
	return true;
}

/// @brief Return the value of the first port located at @a valueptr + 1 
static u16	get_next_port(char** valueptr)
{
	u16 next_port;

	if (*(++valueptr) == NULL)
		next_port = 0;
	else if (is_range_format(*valueptr))
		next_port = get_first_port_range(*valueptr, 0);
	else
		next_port = get_port_unique(*valueptr, 0);

	return next_port;
}

static err_t check_repeated_port(const char* s, u16* const repeated)
{
	err_t	st = SUCCESS;
	char**	values = split((char*)s, ',');
	char**	base = values;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for ( ; *(values + 1) ; values++)
	{
		for (char** it = values + 1 ; *it ; it++)
		{
			if (is_range_format(*it))
			{
				if (is_range_format(*values))
				{
					if (has_range_in_range(*it, *values, repeated) == true)
						goto error;
				}
				else
				{
					if (has_unique_in_range(*it, *values, repeated) == true)
						goto error;
				}
			}
			else
			{
				if (is_range_format(*values))
				{
					if (has_unique_in_range(*values, *it, repeated) == true)
						goto error;
				}
				else
				{	
					u32 p;
					if ((p = get_port_unique(*values, 0)) == get_port_unique(*it , 0))
					{
						*repeated = p;
						goto error;
					}
				}
			}
		}
	}
	free_split(base);
	return st;

error:
	free_split(base);
	return EARGUMENT;
}

/// @brief Return a pointer to the string in string array @a values where port @a tofind is located
static char** find_port(char** values, u16 tofind)
{
	if (tofind == 0)
		return values;

	for ( ; *values ; values++)
	{
		if (is_range_format(*values))
		{
			const u16 first = get_first_port_range(*values, 0);
			if (tofind >= first && tofind <= get_last_port_range(*values, first, 0, 0, 0))
				return values;
		}
		else if (get_port_unique(*values, 0) == tofind)
			return values;
	}
}

static err_t is_last_iteration(u16 currport, const char* s, bool* const is_last)
{
	u64 lenght = 0;
	bool curr_reached = currport == 0;

	char**	values = split((char*)s, ',');
	char**	base = values;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for (; *values ; values++)
	{
		if (is_range_format(*values))
		{
			const u32 first = get_first_port_range(*values, 0);
			const u32 last = get_last_port_range(*values, first, 0, 0, 0);

			if (currport && currport >= first && currport <= last)
			{
				curr_reached = true;
				lenght += last - currport;
			}
			else if (curr_reached)
					lenght += last - first + 1;
		}
		else
		{
			const u32 unique = get_port_unique(*values, 0);

			if (currport && currport == unique)
				curr_reached = true;
			if (curr_reached)
				lenght++;
		}

		if (lenght < MAX_PORTNB)
		{
			*is_last = true;
			goto end;
		}
	}

	*is_last = false;
end:
	free_split(base);
	return SUCCESS;
}

static err_t count_ports(u64* const port_nb, const char* s)
{
	err_t	st = SUCCESS;
	u64 	total = 0;
	portpref_t preffix;
	char**	values = split((char*)s, ',');
	char**	base = values;

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for ( ; *values ; values++)
	{
		if (check_range_format(*values))
		{
			const u32 first = get_first_port_range(*values, &preffix);
			if (first > 0XFFFF || first == 0)
				goto error;
			const u32 last = get_last_port_range(*values, first, 0, 0, &preffix);
			if (last > 0XFFFF || last == 0)
				goto error;
			if ((i32)(last - first) <= 0)
				goto error;

			total += last - first + 1;
		}
		else if (check_unique_format(*values))
		{
			const u32 value = get_port_unique(*values, &preffix);
			if (value > 0XFFFF || value == 0)
				goto error;

			total++;
		}
		else
			goto error;

		if (preffix == PREF_ERROR)
		{
			st = EARGUMENT;
			goto error;
		}
	}
	*port_nb = total;
	free_split(base);
	return st;

error:
	free_split(base);
	PRINT_ERROR(EMSG_INVARG, O_PORT_STR, s);
	return EARGUMENT;
}

/// @brief Copy @a bufflen ports into struct @a parse using string @a s .
/// Store the status of the previous call if s has more than @p bufflen ports.
static err_t copy_ports(parse_t* const parse, u64 bufflen, const char* s)
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

	valueptr = find_port(values, parse->args.currport);

	if (parse->args.currport == 0)
	{
		if (is_range_format(*valueptr))
			parse->args.currport = get_first_port_range(*valueptr, 0);
		else
			parse->args.currport = get_port_unique(*valueptr, 0);
	}
		
	u16 next_iteration_start;
	u64 buffindex = 0;
	portpref_t preffix;
	while (*valueptr && cplen < bufflen)
	{
		if (is_range_format(*valueptr))
		{
			bool is_last = false;
			const u64 lastinrange = get_last_port_range(*valueptr, parse->args.currport, bufflen - cplen, &is_last, &preffix);

			for (u64 value = parse->args.currport ; value <= lastinrange ; value++)
			{
				parse->args.ports[buffindex].value = value;
				parse->args.ports[buffindex++].preffix = preffix;
			}

			cplen += lastinrange - parse->args.currport + 1;

			if (cplen == bufflen)
				next_iteration_start = is_last ? get_next_port(valueptr) : lastinrange + 1;
		}
		else
		{
			parse->args.ports[buffindex].value = get_port_unique(*valueptr, &preffix);
			parse->args.ports[buffindex++].preffix = preffix;
			cplen++;

			if (cplen == bufflen)
				next_iteration_start = get_next_port(valueptr);
		}
		valueptr++;
		if (*valueptr && is_range_format(*valueptr))
			parse->args.currport = get_first_port_range(*valueptr, 0);
	}
	parse->args.currport = next_iteration_start;	

error:
	free_split(values);
	return st;
}

/** @brief Iterative port parser.
 * 	Parses a maximum of 1024 ports into @a parse.
 * 	If there's more than 1024 ports, each next
 * 	call will start from previous call's last port + 1.
 * 
 * 	Ports format: [PREFIX]:<UNIQUE | RANGE>,...
*/
err_t	parse_ports_iteration(const char* s, u64 port_nb, parse_t* const parse)
{
	err_t st = SUCCESS;
	bool is_last_it = false;

	if ((st = is_last_iteration(parse->args.currport, s, &is_last_it)) != SUCCESS)
		goto error;

	/* Limit the number of ports, in all the cases a max of 1024 are copied per call */
	if (BITHAS(parse->opts, O_FULLPORT) == false && port_nb > MAX_PORTNB)
	{
		PRINT_ERROR(EMSG_MAXPORTRANGE, MAX_PORTNB);
		st = EMAXRANGE;
		goto error;
	}

	const u64 bufflen = is_last_it ? port_nb % MAX_PORTNB : MIN(port_nb, MAX_PORTNB);

	if (parse->args.ports == NULL)
	{
		if ((parse->args.ports = malloc(sizeof(*parse->args.ports) * (bufflen + 1))) == NULL)
		{
			PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
			st = ESYSCALL;
			goto error;
		}
	}
	else
		memset(parse->args.ports, 0, MAX_PORTNB);

	/* Copy ports and update iteration status for next iteration */
	if ((st = copy_ports(parse, bufflen, s)) != SUCCESS)
		goto error;

	/* NULL terminated array */
	memset(parse->args.ports + bufflen, 0, sizeof(*parse->args.ports));

	st = is_last_it ? BREAK : SUCCESS;

error:
	return st;
}

err_t	parse_ports(const char** s, parse_t* const parse)
{
	err_t st = SUCCESS;
	u64 port_nb = 0;

	if ((st = count_ports(&port_nb, *s)) != SUCCESS)
		goto error;

	u16 repeated;
	if ((st = check_repeated_port(*s, &repeated)) != SUCCESS)
	{
		PRINT_ERROR(EMSG_REPEATED_PORT, repeated);
		st = EARGUMENT;
		goto error;
	}

	parse->args.totalports = port_nb;

	st = parse_ports_iteration(*s, port_nb, parse);

error:
	return st;
}
