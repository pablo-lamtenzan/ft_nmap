# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <arpa/inet.h>

err_t   parse_spoofed_src_ip(const char** s, parse_t* const parse)
{
    u32 addr;
    if ((addr = inet_addr(*s)) == 0 || addr == 0XFFFFFFFF)
    {
        PRINT_ERROR(EMSG_INVARG, O_EV_IP_STR, *s);
        return EARGUMENT;
    }

    parse->args.scr_ip = addr;
    return SUCCESS;
}
