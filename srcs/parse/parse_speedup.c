# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_speedup(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    // Must be an integer >= 0 && < 250 (0 has not effect maybe put a warning)
}
