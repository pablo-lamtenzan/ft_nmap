# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_data_hex(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    // Suported formats:
    // - 0x42ab24ab24ab
    // - 42ab24ab24ab
    // - \x42\xab\x42\xab

    // Upper or lower cases
}
