
# include <ft_engine.h>
# include <ft_parse.h>

# include <errno.h>

err_t   process_host(parse_t* const parse, const struct sockaddr* const host,
const packets_t* const packets)
{
    err_t st = SUCCESS;

    do
    {
        if (parse->args.nb_threads == 0)
        {
            for (port_t* port = parse->args.ports ; port->value ; port++)
            {
                struct sockaddr saddr = *host;
                ((struct sockaddr_in*)&saddr)->sin_port = port->value;

                routine_data_t* data = gen_routine_data(packets, &saddr, (const parse_t*)parse, port->preffix);
                if (data == NULL)
                {
                    PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
                    st = ESYSCALL;
                    goto error;
                }

                if ((st = process_host_port(data)) != SUCCESS)
                    goto error;

                free_routine_data(data);
            }
        }
        else
        {
            
            for (port_t* port = parse->args.ports ; port->value ; port++)
            {
                struct sockaddr saddr = *host;
                ((struct sockaddr_in*)&saddr)->sin_port = port->value;

                routine_data_t* data = gen_routine_data(packets, &saddr, parse, port->preffix);
                if (data == NULL)
                {
                    PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
                    st = ESYSCALL;
                    goto error;
                }

                ///TODO:
                // 1) Lauch NB_TREADS threads (one per iteration)
                // 2) Then block loop with mutex
                // 3) Then wait for all the threads or timeout and unblock the mutex and repeat the process
                // 4) When i'm on last iteration also block loop and wait
            }
        }
    }
    while (
        parse->args.no_port_iterations == false
        && (st = parse_ports_iteration(parse->args.av_ports, parse->args.totalports, parse)) == SUCCESS
    );

error:
    return st == BREAK ? SUCCESS : st;
}
