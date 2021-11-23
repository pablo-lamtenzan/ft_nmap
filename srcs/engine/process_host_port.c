
# include <ft_engine.h>

err_t	process_host_port(void* x)
{
    const routine_data_t* const data = (const routine_data_t*)x;

    // 1) Inject port & sockaddr into packet before send it
    // ( go into the packet, cast iphdr ... the tipical stuff)

    // Here i need to handle: OS & Version detection, fragmentation and decoys

    // Send the packets following a non specified yet pattern

    // Also receive responses and process the data (whether libpcap allow me receiving
    //  by port (filter by port)) and if is faster than multiplexing in the main)

    // Then the purpose of the routine has terminate, exit
    ///MUST: Receive by timeout (whether i receive here)

    (void)data;
    return SUCCESS; // i think this should not return 
}
