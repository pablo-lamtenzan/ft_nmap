
# include <ft_error.h>
# include <ft_parse.h>
# include <ft_utils.h>

# include <string.h>

err_t parse_all_arguments(const char** av[], parse_t* const parse)
{
    static const char* const arg_str[] = {
        O_HELP_STR,    O_FULLPORT_STR, O_PORT_STR,
        O_IP_STR,      O_FILE_STR,     O_SPEEDUP_STR, 
        O_SCAN_STR,    O_VE_UP_STR,    O_VE_LIGHT_STR,
        O_VE_ALL_STR,  O_OS_UP_STR,    O_OS_LIM_STR,
        O_OS_GSS_STR,  O_OS_MTR_STR,   O_EV_MTU_STR,
        O_EV_FRG_STR,  O_EV_DEC_STR,   O_EV_IP_STR,
        O_EV_IF_STR,   O_EV_SPRT_STR,  O_EV_HDAT_STR,
        O_EV_SDAT_STR, O_EV_RDAT_STR,  O_EV_IPOP_STR,
        O_EV_TTL_STR,  O_EV_RHST_STR,  O_EV_MAC_STR,
        O_EV_BSUM
    };

    static const parse_arg_t arg_f[] = {
        NULL,
        NULL,
        &parse_ports
    };

	err_t	st = SUCCESS;
    u64		index = 0;
    bool	found = false;

    while ((*av)[index])
    {
        for (size_t arg_index = 0 ; arg_index < ARRAYSIZE(arg_str) ; arg_index++)
        {
            if (strncmp((*av)[index], arg_str[arg_index], strlen(arg_str[arg_index])) == 0)
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
					else if ((st = arg_f[arg_index]((*av)[++index], parse)) != SUCCESS)
                    {
                        if (arg_f[arg_index] == &parse_ports && st == BREAK)
                        {
                            parse->args.no_port_iterations = true;
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
