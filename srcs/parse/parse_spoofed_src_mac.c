# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_spoofed_src_mac(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    /// Just validate a MAC and store it in u8[4] or malloc sizeof(u8) * 4
}
