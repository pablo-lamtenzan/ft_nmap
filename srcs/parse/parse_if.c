# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <ifaddrs.h>
# include <net/if.h>
# include <errno.h>
# include <string.h>

err_t   parse_if(const char** s, parse_t* const parse)
{
    struct ifaddrs* ifap = NULL;
    bool found = false;

    if (getifaddrs(&ifap) < 0)
    {
        PRINT_ERROR(EMSG_SYSCALL, "getifaddrs", errno);
        return EARGUMENT;
    }

    for (struct ifaddrs* i = ifap ; i->ifa_next ; i = i->ifa_next)
    {
        if (i->ifa_name == NULL || i->ifa_addr->sa_family != AF_INET)
            continue ;
        if (strncmp(i->ifa_name, *s, strlen(i->ifa_name) + 1) == 0)
        {
            if (i->ifa_flags & IFF_UP)
                found = true;
        }
    }

    if (found == false)
        PRINT_ERROR(EMSG_INVARG, O_EV_IF_STR, *s);
    else
        parse->args.interface = *s;

    freeifaddrs(ifap);
    return found == true ? SUCCESS : EARGUMENT;
}
