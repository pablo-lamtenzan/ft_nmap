
# include <ft_engine.h>

# include <stdlib.h>

void	free_routine_data(routine_data_t* data)
{
	for (register u8** i = data->pks_data ; *i ; i++)
		free(*i);
	free(data->pks_data);
	free(data->pks_len);
	free(data);
}
