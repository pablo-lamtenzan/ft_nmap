
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_utils.h>

# include <string.h>

///TODO: Parse ip header options `parse_ip_opts.c`

static inline err_t handle_invalid_option_combination(parse_t* const parse)
{
    err_t st = SUCCESS;

    if (BITHAS(parse->opts, O_IP) && BITHAS(parse->opts, O_FILE))
    {
        PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_IP_STR, O_FILE_STR);
        st = EARGUMENT;
    }

    if (BITHAS(parse->opts, O_EV_HDAT | O_EV_SDAT | O_EV_RDAT))
    {
        if (BITHAS(parse->opts, O_EV_HDAT) && BITHAS(parse->opts, O_EV_SDAT | O_EV_RDAT))
        {
            PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_EV_HDAT_STR, O_EV_SDAT_STR " | " O_EV_RDAT_STR);
            st = EARGUMENT;
        }
        else if (BITHAS(parse->opts, O_EV_SDAT) && BITHAS(parse->opts, O_EV_HDAT | O_EV_RDAT))
        {
            PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_EV_SDAT_STR , O_EV_HDAT_STR " | " O_EV_RDAT_STR);
            st = EARGUMENT;
        }
        else if (BITHAS(parse->opts, O_EV_RDAT) && BITHAS(parse->opts, O_EV_HDAT | O_EV_SDAT))
        {
            PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_EV_RDAT_STR , O_EV_HDAT_STR " | " O_EV_SDAT_STR);
            st = EARGUMENT;
        }
    }

    if (BITHAS(parse->opts, O_EV_DEC))
    {
        if (BITHAS(parse->opts, O_VE_UP | O_VE_LIGHT | O_VE_ALL))
        {
            PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_EV_DEC_STR, O_VE_UP_STR " | " O_VE_LIGHT_STR " | " O_VE_ALL_STR);
            st = EARGUMENT;
        }
        if (BITHAS(parse->opts, O_S_TCPCON))
        {
            PRINT_ERROR(EMGS_IMCOMPATIBLE_OPTS, O_EV_DEC_STR, O_SCAN_STR " " O_S_TCPCON_STR);
            st = EARGUMENT;
        }
    }

    return st;
}

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

                if (arg_f[arg_index] != &parse_scan)
                {
                    /* Skip all scan wrapped into --scan */
                    const u64 mask = arg_index > 6 ? arg_index + 12 : arg_index;
            
                    if (BITHAS(parse->opts, 1UL << mask))
                    {
                        PRINT_ERROR(EMGS_DUPLICATE_OPT, arg_str[arg_index]);
                        st = EARGUMENT;
                        goto error;
                    }

                    BITADD(parse->opts, 1UL << mask);
                }

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
                        else if ((arg_f[arg_index] == &parse_ips && st == BREAK)
                        || (arg_f[arg_index] == &parse_file && st == BREAK))
                        {
                            parse->args.no_ip_iterations = true;
                            st = SUCCESS;
                        }
                        else
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
    st = handle_invalid_option_combination(parse);
error:
	return st;
}
