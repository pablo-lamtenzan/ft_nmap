# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t   parse_os_detection_tries(const char** s, parse_t* const parse)
{
    for (register u64 i = **s == '-' ; (*s)[i] ; i++)
    {
        if (ISNUM((*s)[i]) == false)
        {
            PRINT_ERROR(EMSG_INVARG, O_OS_MTR_STR, *s);
            return EARGUMENT;
        }
    }

    const i32 value = atoi(*s);

    if (ISVAL_INRANGE(value, 1, 5) == false)
    {
        PRINT_ERROR(EMSG_INV_VALUE, O_OS_MTR_STR, *s, 1, 5);
        return EARGUMENT;
    }

    parse->args.os_det_tries = value;
    return SUCCESS;
}
