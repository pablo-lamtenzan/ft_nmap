
# include <ft_error.h>

# include <ifaddrs.h>
# include <net/if.h>
# include <errno.h>

# include <string.h>

err_t getsockfromif(struct sockaddr* const res, const char* ifname)
{
    struct ifaddr* ifap = NULL;

    if (getifaddrs(&ifap) < 0)
    {
        PRINT_ERROR(EMSG_SYSCALL, "getifaddrs", errno);
        return EARGUMENT;
    }

	if (ifname == NULL)
	{
		for (struct ifaddrs* ifs = ifap ; ifs->ifa_next ; ifs = ifs->ifa_next)
		{
			if (ifs->ifa_addr->sa_family != AF_INET)
				continue ;
			if (ifs->ifa_flags & IFF_UP)
			{
				*res = *ifs->ifa_addr;
				break ;
			}
		}
	}
	else
	{
		for (struct ifaddrs* ifs = ifap ; ifs->ifa_next ; ifs = ifs->ifa_next)
		{
			if (strncmp(ifs->ifa_name, *ifname, strlen(ifname) + 1) != 0)
				continue ;
			*res = *ifs->ifa_addr;
			break ;
		}
	}

	freeifaddrs(ifap);
	return SUCCESS;
}