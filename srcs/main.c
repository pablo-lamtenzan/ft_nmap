
# include <ft_error.h>
# include <ft_nmap.h>

#include <ft_parse.h> // remove this

# include <stdlib.h>

# include <debug.h>

__attribute__ ((always_inline))
static inline void free_all(parse_t* parse)
{
    free_parse(parse);
}

int main(int ac, const char* av[])
{
    err_t st = SUCCESS;

    parse_t parse = {0};

    av++;
    if ((st = parse_all_arguments(&av, &parse)) != SUCCESS)
        goto error;

error:
    free_all(&parse);
    return st;
}
