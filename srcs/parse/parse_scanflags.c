# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <string.h>

err_t   parse_scanflags(const char** s, parse_t* const parse)
{
    static const char* const tcpflags[] = {
        "URG",
        "ACK",
        "PSH",
        "RST",
        "SYN",
        "FIN"
    };

    if (*s == NULL)
    {
        PRINT_ERROR(EMSG_EXPECTED_ARG, O_SCAN_STR " " O_S_TCPCUS_STR);
        return EARGUMENT;
    }

    u8 buff[0X13] = {0};

    {
        const u64 lenght = strlen(*s);

        if (lenght > ARRAYSIZE(buff) || lenght % 3)
        {
            PRINT_ERROR(EMSG_INVARG, O_SCAN_STR " " O_S_TCPCUS_STR, *s);
            return EARGUMENT;
        }

        memcpy(buff, *s, lenght);
    }

    bool found;

    char prev;
    for (register u64 i = 0 ; buff[i] ; )
    {
        prev = buff[i + 3];
        buff[i + 3] = 0;

        found = false;
        for (register u64 y = 0 ; y < ARRAYSIZE(tcpflags) ; y++)
        {
            if (strncmp(&buff[i], tcpflags[y], 4) == 0)
            {
                found = true;
                BITADD(parse->args.scanflags, 1 << y);
                break ;
            }
        }

        if (found == false)
        {
            PRINT_ERROR(EMSG_INVARG, O_SCAN_STR " " O_S_TCPCUS_STR, &buff[i]);
            return EARGUMENT;
        }

        i += 3;
        if (prev == 0)
            break ;
        else
            buff[i] = prev;
    }

    return SUCCESS;
}
