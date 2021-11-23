# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>

err_t   parse_data_string(const char** s, parse_t* const parse)
{
    if (BITHAS(parse->opts, O_EV_RDAT))
    {
        free((i8*)parse->args.data);
        BITDEL(parse->opts, O_EV_RDAT);
    }

    parse->args.data = *s;
    return SUCCESS;
}
