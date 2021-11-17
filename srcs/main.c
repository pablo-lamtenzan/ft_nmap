
# include <ft_error.h>
# include <ft_nmap.h>

int main(int ac, const char* av[])
{
    err_t st = SUCCESS;

    parse_t parse;

    if ((st = parse_all_arguments(&av, &parse)) != SUCCESS)
        goto error;

error:
    return st;
}