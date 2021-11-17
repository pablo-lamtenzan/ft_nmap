
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>

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
	portpref_t preffix = NONE;

	if ((*valueptr)[1] == ':')
	{
		switch (**valueptr)
		{
			case 'T':
				preffix = TCP;
				break ;
			case 'U':
				preffix = UDP;
				break ;
			case 'S':
				preffix = SCTP;
				break ;
		}
		if (valueptr != NONE)
			*valueptr += 2;
	}

	return preffix;
}

/// @brief Return true if @a valueptr follow ranged port format
static bool is_range_format(char* valueptr)
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

/// @brief Return true if @a valueptr follow unique port format
static bool is_unique_format(char* valueptr)
{
	skip_preffix(&valueptr);

	for ( ; *valueptr ; valueptr++)
		if (!ISNUM(*valueptr))
			return false;
	return true;
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
	u64 sep_index = get_sep_index(valueptr, '-');
	memcpy(buff, valueptr, sep_index);
	return atoi(buff);
}

/// @brief Get numerical last range value from string @a valueptr following ranged port format
static u32	get_last_port_range(char* valueptr, u16 start, u64 max, bool* const is_last, portpref_t* const preffix)
{
	const portpref_t pref = skip_preffix(&valueptr);

	if (preffix)
		*preffix = pref;

	char buff[0X10] = {0};

	u64 sep_index = get_sep_index(valueptr, '-');
	memcpy(buff, valueptr + sep_index + 1, strlen(&valueptr[sep_index + 1]));

	u32 value = atoi(buff);

	if (is_last)
	{
		if (value > start + max)
			value = start + max;
		else
			*is_last = true;
	}

	return value;
}

/// @brief Return the value of the first port located at @a valueptr + 1 
static u16	get_next_port(char* valueptr)
{
	u16 next_port;

	if (++valueptr == NULL)
		next_port = 0;
	else if (is_range_format(valueptr))
		next_port = get_first_port_range(valueptr, 0);
	else
		next_port = get_port_unique(valueptr, 0);

	return next_port;
}

/// @brief Return a pointer to the string in string array @a values where port @a tofind is located
static char* find_port(char** values, u16 tofind)
{
	if (tofind == 0)
		return *values;

	for ( ; *values ; values++)
	{
		if (is_range_format(*values))
		{
			u16 first = get_first_port_range(*values, 0);
			if (tofind >= first && tofind <= get_last_port_range(*values, first, 0, 0, 0))
				return *values;
		}
		else if (get_port_unique(*values, 0) == tofind)
			return *values;
	}
}

/// @brief Check port format validation, port value validation, count the total port number
/// and check if this is the last iteration for process all given ports
static err_t count_ports(u64* const port_nb, const char* s, u16 curr_port, bool* const is_last_iteration)
{
	u64 total = 0;
	u64 total_until_end = 0;
	bool curr_reached = false;

	err_t	st = SUCCESS;
	char**	values = split(s, ',');

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	for ( ; *values ; values++)
	{
		if (is_range_format(*values))
		{
			u32 first = get_first_port_range(*values, 0);
			if (first > 0XFFFF || first == 0)
				goto error;
			u32 last = get_last_port_range(*values, first, 0, 0, 0);
			if (last > 0XFFFF || last == 0)
				goto error;

			total += last - first;

			if (curr_port && curr_port >= first && curr_port <= last)
				curr_reached = true;
			if (curr_reached)
				total_until_end += last - first;
		}
		else if (is_unique_format(*values))
		{
			u32 value = get_port_unique(*values, 0);
			if (value > 0XFFFF || values == 0)
				goto error;

			total++;

			if (curr_port && curr_port == value)
				curr_reached = true;
			if (curr_reached)
				total_until_end++;
		}
		else
			goto error;
	}

	*is_last_iteration = (curr_port == 0 && total < MAX_PORTNB) || (curr_port && total_until_end < MAX_PORTNB);
	free(values);
	return st;

error:
	free(values);
	PRINT_ERROR(EMSG_INVARG, O_PORT_STR, s);
	return EARGUMENT;
}

/// @brief Copy @a bufflen ports into struct @a parse using string @a s .
/// Store the status of the previous call if s has more than @p bufflen ports.
static err_t copy_ports(parse_t* const parse, u64 bufflen, const char* s)
{
	err_t	st = SUCCESS;
	u64		cplen = 0;
	char*	valueptr;
	char**	values = split(s, ',');

	if (values == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		st = ESYSCALL;
		goto error;
	}

	valueptr = find_port(values, parse->args.currport);

	u16 next_iteration_start;
	u64 buffindex = 0;
	while (valueptr && cplen < bufflen)
	{
		portpref_t preffix;
		if (is_range_format(valueptr))
		{
			bool is_last;
			const u64 lastinrange = get_last_port_range(valueptr, parse->args.currport, bufflen - cplen, &is_last, &preffix);

			for (u64 value = parse->args.currport ; value <= lastinrange ; value++)
			{
				parse->args.ports[buffindex].value = value;
				parse->args.ports[buffindex++].preffix = preffix;
			}

			cplen += lastinrange - parse->args.currport;
			next_iteration_start = is_last ? get_next_port(valueptr) : lastinrange + 1;
		}
		else
		{
			parse->args.ports[buffindex].value = get_port_unique(valueptr, &preffix);
			parse->args.ports[buffindex++].preffix = preffix;
			cplen++;
			next_iteration_start = get_next_port(valueptr);
		}
		valueptr++;
	}
	parse->args.currport = next_iteration_start;

error:
	free(values);
	return st;
}

/** @brief Iterative port parser.
 * 	Parses a maximum of 1024 ports into @a parse.
 * 	If there's more than 1024 ports, each next
 * 	call will start from previous call's last port + 1.
 * 
 * 	Ports format: [PREFIX]:<UNIQUE | RANGE>,...
*/
err_t	parse_ports(const char* s, parse_t* const parse)
{
	///NOTE: Call it once on parse, call it more after complete parse (if option enabled (just need a pointer to ports args to work))

	err_t st;
	u64 port_nb = 0;
	bool islast_iteration = false;

	/* Check format, validate values, get lenght and iteration status */
	if ((st = count_ports(&port_nb, s,parse->args.currport, &islast_iteration)) != SUCCESS)
		goto error;

	st = islast_iteration ? BREAK : SUCCESS;

	///TODO: Max ports is 1024, this will be optional with an option
	/* Enable iteration */
	if (1 && port_nb > MAX_PORTNB)
	{
		PRINT_ERROR(EMSG_MAXPORTRANGE, MAX_PORTNB);
		st = EMAXRANGE;
		goto error;
	}

	const u64 bufflen = islast_iteration ? port_nb % MAX_PORTNB : MIN(port_nb, MAX_PORTNB);

	/* Allocate a maximum of 1024 ports per iteration */
	free(parse->args.ports);

	if ((parse->args.ports = malloc(sizeof(*parse->args.ports) * bufflen)) == NULL)
	{
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		st = ESYSCALL;
		goto error;
	}

	/* Copy ports and update iteration status for next iteration */
	if ((st = copy_ports(parse, bufflen, s)) != SUCCESS)
	{
		free(parse->args.ports);
		goto error;
	}

error:
	return st;
}
