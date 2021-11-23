
# include <ft_types.h>
# include <ft_utils.h>
# include <ft_error.h>

# include <stdlib.h>

void free_parse(parse_t* const parse)
{
    free(parse->args.ports);
    free(parse->args.ips);
    if (BITHAS(parse->opts, O_EV_RDAT))
        free((i8*)parse->args.data);
    free((i8*)parse->args.file);
}
