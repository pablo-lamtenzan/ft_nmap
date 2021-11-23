
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_utils.h>

# include <string.h>

///TODO: Seem some arguments follows and specific order in subject
/// (port before ip, then all options)

///TODO: Restrict 255.255.255.255 (broadcast has no sense while receiving)

///TODO: Check for invalid options combination (read man while doing it)

err_t parse_all_arguments(const char** av[], parse_t* const parse)
{
    static const parse_arg_t arg_f[] = {
        NULL,
        NULL,
        &parse_ports,
        &parse_ips,
        &parse_file,
        &parse_speedup,
        &parse_scan,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        &parse_os_detection_tries,
        &parse_mtu,
        NULL,
        &parse_decoy,
        &parse_spoofed_src_ip,
        &parse_if,
        &parse_spoofed_src_port,
        &parse_data_hex,
        &parse_data_string,
        &parse_data_lenght,
        &parse_ip_opts,
        &parse_ttl,
        NULL,
        &parse_spoofed_src_mac,
        NULL
    };

	err_t	st = SUCCESS;
    u64		index = 0;
    bool	found = false;

    while ((*av)[index])
    {
        for (size_t arg_index = 0 ; arg_index < ARRAYSIZE(arg_str) ; arg_index++)
        {
            if (strncmp((*av)[index], arg_str[arg_index], strlen(arg_str[arg_index]) + 1) == 0)
            {
				found = true;
				BITADD(parse->opts, 1 << arg_index);

				if (arg_f[arg_index])
				{
					if ((*av)[index + 1] == NULL)
					{
						PRINT_ERROR(EMSG_EXPECTED_ARG, (*av)[index]);
						st = EARGUMENT;
						goto error;
					}
					else if ((st = arg_f[arg_index](&(*av)[++index], parse)) != SUCCESS)
                    {
                        if (arg_f[arg_index] == &parse_ports && st == BREAK)
                        {
                            parse->args.no_port_iterations = true;
                            st = SUCCESS;
                        }
                        else if ((arg_f[arg_index] == &parse_ips && st == BREAK) || (arg_f[arg_index] == &parse_file && st == BREAK))
                        {
                            parse->args.no_ip_iterations = true;
                            st = SUCCESS;
                        }
						goto error;
                    }
				}
            }
        }
		if (found == false)
		{
			PRINT_ERROR(EMSG_UNKNOWN_OPT, (*av)[index]);
			st = EARGUMENT;
			goto error;
		}
        index++;
    }

	*av += index;
error:
	return st;
}
