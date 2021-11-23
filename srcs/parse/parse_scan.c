# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <string.h>

err_t   parse_scan(const char** s, parse_t* const parse)
{
    static const char* const scans[] = {
        O_S_TCPSYN_STR,
        O_S_TCPCON_STR,
        O_S_TCPACK_STR,
        O_S_TCPWIN_STR,
        O_S_TCPMAI_STR,
        O_S_UDP_STR,
        O_S_TCPNUL_STR,
        O_S_TCPFIN_STR,
        O_S_TCPXMA_STR,
        O_S_TCPCUS_STR,
        O_S_SCTPIN_STR,
        O_S_SCTPCE_STR,
        O_S_IPPROT_STR
    };

    static const char* const alliases[] = {
        "SYN",
        "CON",
        "ACK",
        "WINDOW",
        "MAIMON",
        "UDP",
        "NULL",
        "FIN",
        "XMAS",
        O_S_TCPCUS_STR,
        "INIT",
        "ECHO",
        "IPPROTO"
    };

	err_t st = SUCCESS;

	bool found = false;
	bool found_one = false;
	for ( ; s && *s ; )
	{
		found = false;
		for ( register u64 i = 0 ; i < ARRAYSIZE(scans) ; i++)
		{
			if (strncmp(*s, scans[i], strlen(scans[i]) + 1) == 0
			|| strncmp(*s, alliases[i], strlen(alliases[i]) + 1) == 0)
			{
				found = true;
				found_one = true;
				BITADD(parse->opts, 1 << (i + 6));
				s++;
				if (s && i == 9)
				{
					if ((st = parse_scanflags(s, parse)) != SUCCESS)
						return st;
					s++;
				}
				break ;
			}
		}

		if (found == false)
		{
			for (register u64 i = 0 ; i < ARRAYSIZE(arg_str) ; i++)
			{
				if (strncmp(*s, arg_str[i], strlen(arg_str[i]) + 1) == 0)
				{
					found = true;
					break ;
				}
			}
			break ;
		}
	}

	if (found == false || found_one == false)
	{
		if (found_one == false && found == true)
			PRINT_ERROR(EMSG_EXPECTED_ARG, O_SCAN_STR);
		else
			PRINT_ERROR(EMSG_INVARG, O_SCAN_STR, *s);
		st = EARGUMENT;
	}
	s--;
	return st;
}
