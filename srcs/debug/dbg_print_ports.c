
# include <ft_types.h>
# include <ft_error.h>

void dbg_print_ports(port_t* ports)
{
    DEBUG("Print ports (port addr: %p)\n", ports);
    u64 i = 0;
    for ( ; ports[i].value != 0 ; i++)
        DEBUG("-> %d:[%hu]\n", ports[i].preffix, ports[i].value);
    DEBUG("Total ports are [%lu]\n", i);
}
