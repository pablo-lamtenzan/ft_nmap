# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t	parse_mtu(const char** s, parse_t* const parse)
{
	for (register u64 i = **s == '-' ; (*s)[i] ; i++)
	{
		if (ISNUM((*s)[i]) == false)
		{
			PRINT_ERROR(EMSG_INVARG, O_EV_MTU_STR, *s);
			return EARGUMENT;
		}
	}

	register const i64 value = atol(*s);

	if (value <= 0 || value % 8)
	{
		PRINT_ERROR(EMSG_INV_MTU, *s);
		return EARGUMENT;
	}

	parse->args.mtu = value;

	return SUCCESS;
}
