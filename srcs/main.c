
# include <ft_error.h>
# include <ft_nmap.h>
# include <ft_parse.h>

# include <stdlib.h>
# include <unistd.h>
# include <time.h>

# include <debug.h>

__attribute__ ((always_inline))
static inline void free_all(parse_t* parse)
{
    free_parse(parse);
}

// NOTE: Use pipes to comunicate main <-> threads, close connextion when thread end (no mutex seeem to be neaded)

int main(int ac, const char* av[])
{
    err_t st = SUCCESS;

    parse_t parse = {0};

    srand(time(NULL));

    av++;
    if ((st = parse_all_arguments(&av, &parse)) != SUCCESS)
        goto error;

    dbg_parse_opts(&parse.args);

error:
    free_all(&parse);
    return st;
}
