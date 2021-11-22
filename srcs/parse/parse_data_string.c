# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_data_string(const char** s, parse_t* const parse)
{
    parse->args.data = *s;
    return SUCCESS;
}
