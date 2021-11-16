
# pragma once

# define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))

# define MIN(l, r) ((l) < (r) ? (l) : (r))
# define MAX(l, r) ((l) > (r) ? (l) : (r))
# define ABS(x) ((x) > 0 ? (x) -(x))

# define ISNUM(x) ((x) >= '0' && (x) <= '9')
# define ISUPPER(x) ((x) >= 'A' && (x) <= 'Z')
# define ISLOWER(x) ((x) >= 'a' && (x) <= 'z')
# define ISALFA(x) (ISUPPER(x) || ISLOWER(x))
# define ISALNUM(x) (ISALFA(x) || ISNUM(x))
# define ISHEX(x) (ISNUM(x) || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
