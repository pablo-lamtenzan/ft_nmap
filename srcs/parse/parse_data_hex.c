# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <string.h>
# include <stdlib.h>

err_t	parse_data_hex(const char** s, parse_t* const parse)
{
	err_t st = SUCCESS;

	if (BITHAS(parse->opts, O_EV_RDAT))
	{
        free((i8*)parse->args.data);
		BITDEL(parse->opts, O_EV_RDAT);
	}

	const char* prev = *s;

	if (**s == '\\')
	{
		for (register u64 i = 0 ; (*s)[i] ; i++)
		{
			if ((*s)[i] == '\\' && (*s)[i + 1] && (*s)[i + 1] == 'x')
				i+= 2;
			else
				goto error;
			
			if (*s[i])
			{
				register u64 y = 0;
				while ((*s)[i] && (*s)[i] != '\\')
				{
					if (ISHEX((*s)[i]))
					{
						y++;
						i++;
					}
					else
						goto error;
				}
				if (y == 0 || y > 2)
					goto error;
				i--;
			}
			else
				goto error;
		}
	}
	else
	{
		if (**s == '0')
		{
			if (*(*s + 1) != 'X' || (*(s + 1) && *(*s + 1) != 'x'))
				*s += 2;
			else
				goto error;
		}

		if (**s == 0)
			goto error;
		for (register u64 i = 0 ; (*s)[i] ; i++)
		{
			if (ISHEX((*s)[i]) == false)
				goto error;
		}
	}

	parse->args.data = *s;
    return SUCCESS;

error:
    PRINT_ERROR(EMSG_INVARG, O_EV_HDAT_STR, prev);
    return EARGUMENT;
}
