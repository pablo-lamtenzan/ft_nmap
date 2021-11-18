
# include <stdlib.h>

///TODO: Use my memcpy

# include <string.h>

void free_split(char** base)
{
    size_t i = 0;
    while(base[i]) {
        free(base[i]);
        i++;
    }
    free(base);
    base = NULL;
}

char **split(char *string, const char delimiter)
{
    int length = 0, count = 0, i = 0, j = 0;
    while(*(string++))
    {
        if (*string == delimiter) count++;
        length++;
    }

    string -= (length + 1); // string was incremented one more than length
    char **array = (char **)malloc(sizeof(char *) * (length + 1));
    if (!array)
        return NULL;

    char ** base = array;
    for(i = 0; i < (count + 1); i++)
    {
        j = 0;
        while(string[j] != delimiter)
            j++;
        j++;

        *array = (char *)malloc(sizeof(char) * j);
        if (!*array)
        {
            free_split(base);
            return NULL;
        }

        memcpy(*array, string, (j-1));
        (*array)[j - 1] = '\0';
        string += j;
        array++;
    }

    *array = '\0';
    return base;  
}
