# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_ip_opts(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    // S|R [route]|L [route]|T|U ... 
    // R, T, or U to request record-route, record-timestamp, or both options together
    // Loose or strict source routing may be specified with an L or S followed by a space and then a space-separated list of IP addresses.
}
