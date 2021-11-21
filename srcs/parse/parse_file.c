# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

err_t   parse_file(const char** s, parse_t* const parse)
{
    (void)s;
    (void)parse;
    return SUCCESS;

    // 1) Open file, read, cp removing '\n'
    // 2) Call parse_ips
    // 3) Store the file pointer
}
