# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t   parse_spoofed_src_port(const char** s, parse_t* const parse)
{
    for (register u64 i = **s == '-' ; (*s)[i] ; i++)
    {
        if (ISNUM((*s)[i]) == false)
        {
            PRINT_ERROR(EMSG_INVARG, O_EV_SPRT_STR, *s);
            return EARGUMENT;
        }
    }

    const i32 value = atoi(*s);

    if (ISVAL_INRANGE(value, 1, 255) == false)
    {
        PRINT_ERROR(EMSG_INV_VALUE, O_EV_SPRT_STR, *s, 1, 255);
        return EARGUMENT;
    }

    parse->args.scr_port = value;
    return SUCCESS;
}
