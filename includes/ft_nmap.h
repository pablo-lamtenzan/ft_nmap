
# pragma once

# include <ft_types.h>

# define MAX_PORTNB 1024

err_t   parse_all_arguments(const char** av[], parse_t* const parse);
void    free_parse(parse_t* const parse);
