# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_mtu(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    /// Must be > 0 and multiple of 8
}
