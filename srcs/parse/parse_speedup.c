# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t   parse_speedup(const char** s, parse_t* const parse)
{
    for (register u64 i = 0 ; (*s)[i] ; i++)
    {
        if (ISNUM((*s)[i]) == false)
        {
            PRINT_ERROR(EMSG_INVARG, O_SPEEDUP_STR, *s);
            return EARGUMENT;
        }
    }

    const i32 value = atoi(*s);

    if (ISVAL_INRANGE(value, 0, 250) == false)
    {
        PRINT_ERROR(EMSG_INV_VALUE, O_SPEEDUP_STR, *s, 0, 255);
        return EARGUMENT;
    }

    if (value == 0)
        PRINT_ERROR(EMSG_NOEFFECT_SPEEDUP, O_SPEEDUP_STR);

    parse->args.nb_threads = value;
    return SUCCESS;
}
