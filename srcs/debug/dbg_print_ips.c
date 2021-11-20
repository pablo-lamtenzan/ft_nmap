
# include <ft_types.h>
# include <ft_error.h>

# include <arpa/inet.h>

void dbg_print_ips(u32* ips)
{
    DEBUG("Print ips (ip addr: %p)\n", ips);
    u64 i = 0;
    for ( ; ips[i] != 0 ; i++)
        DEBUG("-> [%s]\n", inet_ntoa((struct in_addr){ips[i]}));
    DEBUG("Total ips are [%lu]\n", i);
}
