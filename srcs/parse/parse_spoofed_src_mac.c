# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <stdlib.h>
# include <string.h>
# include <errno.h>

# define ISZEROMAC(mac) (                   \
    (mac)[0] == '0' && (mac)[1] == '0'      \
    && (mac)[3] == '0' && (mac)[4] == '0'   \
    && (mac)[6] == '0' && (mac)[7] == '0'   \
    && (mac)[9] == '0' && (mac)[10] == '0'  \
    && (mac)[12] == '0' && (mac)[13] == '0' \
    && (mac)[15] == '0' && (mac)[16] == '0' \
)

# define ISCOLON(x) ((x) == ':')
# define ISVALIDMAC(mac) (					\
	ISHEX((mac)[0]) && ISHEX((mac)[1])		\
	&& ISCOLON((mac)[2])					\
	&& ISHEX((mac)[3])	&& ISHEX((mac)[4])	\
	&& ISCOLON((mac)[5])					\
	&& ISHEX((mac)[6]) && ISHEX((mac)[7])	\
	&& ISCOLON((mac)[8])					\
	&& ISHEX((mac)[9]) && ISHEX((mac)[10])	\
	&& ISCOLON((mac)[11])					\
	&& ISHEX((mac)[12])	&& ISHEX((mac)[13])	\
	&& ISCOLON((mac)[14])					\
	&& ISHEX((mac)[15]) && ISHEX((mac)[16])	\
    && ISZEROMAC(mac) == false              \
    && ((mac)[17] == 0)                     \
)

err_t   parse_spoofed_src_mac(const char** s, parse_t* const parse)
{
    if (strlen(*s) < 17 || ISVALIDMAC(*s) == false)
    {
        PRINT_ERROR(EMSG_INVARG, O_EV_MAC_STR, *s);
        return EARGUMENT;
    }

    char** base = split((char*)*s, ':');
    if (base == NULL)
    {
        PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
        return ESYSCALL;
    }

    parse->args.src_mac[0] = ft_strtol(base[0], 0, 16);
    parse->args.src_mac[1] = ft_strtol(base[1], 0, 16);
    parse->args.src_mac[2] = ft_strtol(base[2], 0, 16);
    parse->args.src_mac[3] = ft_strtol(base[3], 0, 16);
    parse->args.src_mac[4] = ft_strtol(base[4], 0, 16);
    parse->args.src_mac[5] = ft_strtol(base[5], 0, 16);

    free_split(base);

    return SUCCESS;
}
