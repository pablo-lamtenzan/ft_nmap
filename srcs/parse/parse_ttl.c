# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t   parse_ttl(const char** s, parse_t* const parse)
{
    for (register u64 i = **s == '-' ; (*s)[i] ; i++)
    {
        if (ISNUM((*s)[i]) == false)
        {
            PRINT_ERROR(EMSG_INVARG, O_EV_TTL_STR, *s);
            return EARGUMENT;
        }
    }

    i32 value = atoi(*s);

    if (ISVAL_INRANGE(value, 0, 255) == false)
    {
        PRINT_ERROR(EMSG_INV_VALUE, O_EV_TTL_STR, *s, 0, 255);
        return EARGUMENT;
    }

    parse->args.ttl = value;
    return SUCCESS;
}
