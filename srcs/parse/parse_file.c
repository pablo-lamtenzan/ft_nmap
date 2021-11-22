# include <ft_error.h>
# include <ft_parse.h>
# include <ft_nmap.h>
# include <ft_utils.h>
# include <ft_libc.h>

# include <errno.h>
# include <stdlib.h>
# include <string.h>

# define CPCAP 1024

err_t	parse_file(const char** s, parse_t* const parse)
{
	FILE* fp = fopen(*s, "r");
	if (fp == NULL)
	{
		if (errno == EINVAL)
		{
			PRINT_ERROR(EMSG_UNKOWN_FILENAME, *s);
			return EARGUMENT;
		}
		else
		{
			PRINT_ERROR(EMSG_SYSCALL, "fopen", errno);
			return ESYSCALL;
		}
		
	}

	i8* buff = malloc(sizeof(i8) * (CPCAP + 1));
	if (buff == NULL)
	{
		fclose(fp);
		PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
		return ESYSCALL;
	}

	register size_t readbytes = 0;
	u64 exp = 1;
	for (register u64 i = 0 ; fread(&buff[i], sizeof(*buff), 1, fp) == 1 ; )
	{
		if (buff[i] != '\n')
		{
			readbytes++; 
			if (++i > CPCAP * exp)
			{
				i8* auxbuff = malloc(sizeof(*buff) * (CPCAP * ++exp));
				if (auxbuff == NULL)
				{
					fclose(fp);
					free(buff);
					PRINT_ERROR(EMSG_SYSCALL, "malloc", errno);
					return ESYSCALL;
				}
				memcpy(auxbuff, buff, CPCAP * (exp - 1));
				free(buff);
				buff = auxbuff;
			}
		}
	}
	buff[readbytes] = 0;

	fclose(fp);

	err_t st = parse_ips((const char**)&buff, parse);

	parse->args.file = buff;

	return st;
}
