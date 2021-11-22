# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <unistd.h>
# include <stdlib.h>

err_t   parse_data_lenght(const char** s, parse_t* const parse)
{
    for (register u64 i = **s == '-' ; (*s)[i] ; i++)
    {
        if (ISNUM((*s)[i]) == false)
            goto error;
    }

    const i32 lenght = atoi(*s);

    if (lenght < 0 || lenght > 0XFFFF)
    {
        PRINT_ERROR(EMSG_INV_VALUE, O_EV_RDAT_STR, *s, 0X0, 0XFFFF);
        return EARGUMENT;
    }

    register u8* const buff = malloc(sizeof(u8) * lenght + 1);
    if (buff == NULL)
    {
        PRINT_ERROR(EMSG_SYSCALL, ESYSCALL);
        return ESYSCALL;
    }

    for (register u64 i = 0 ; i < lenght ; i++)
        buff[i] = rand() % 0XFF;
    buff[lenght] = 0;

    parse->args.data = (const u8*)buff;
    return SUCCESS;

error:
    PRINT_ERROR(EMSG_INVARG, O_EV_RDAT_STR, *s);
    return EARGUMENT;
}
