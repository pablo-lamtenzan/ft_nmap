
# include <ft_types.h>

# include <stdlib.h>

void free_parse(parse_t* const parse)
{
    free(parse->args.ports);
    free(parse->args.ips);
}
