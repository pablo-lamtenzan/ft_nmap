# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <errno.h>
# include <arpa/inet.h>
# include <string.h>

err_t   parse_decoy(const char** s, parse_t* const parse)
{
    static const char me[] = "ME";

    if (strncmp(*s, me, strlen(*s) + 1) == 0)
    {
        PRINT_ERROR(EMSG_DECOY_NEEDDECOYS, O_EV_DEC_STR);
        return EARGUMENT;
    }

    char** base = split((char*)*s, ',');
    if (base == NULL)
    {
        PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
        return ESYSCALL;
    }

    char** values = base;

    for ( ; *values ; values++)
    {
        in_addr_t ip;
        if (((ip = inet_addr(*values)) == 0 || ip == ~(in_addr_t)0)
        && strncmp(*values, me, sizeof(me)) != 0)
        {
            PRINT_ERROR(EMSG_INVARG, O_EV_DEC_STR, *values);
            free_split(base);
            return EARGUMENT;
        }
    }

    parse->args.decoys = *s;
    free_split(base);
    return SUCCESS;
}
