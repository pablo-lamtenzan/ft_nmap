#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <errno.h>
#ifdef NEED_DECLARATION_ERRNO
extern int errno;
#endif

#ifndef ULONG_MAX
#define        ULONG_MAX        ((unsigned long)(~0L))                /* 0xFFFFFFFF */
#endif
#ifndef LONG_MAX
#define        LONG_MAX        ((long)(ULONG_MAX >> 1))        /* 0x7FFFFFFF */
#endif
#ifndef LONG_MIN
#define        LONG_MIN        ((long)(~LONG_MAX))                /* 0x80000000 */
#endif

#ifndef ISSPACE
# define ISSPACE(x) ((x) == ' ')
#endif

#ifndef ISDIGIT
# define ISDIGIT(x) ((x) >= '0' && (x) <= '9')
#endif

#ifndef ISUPPER
# define ISUPPER(x) ((x) >= 'A' && (x) <= 'Z') 
#endif

#ifndef ISLOWER
# define ISLOWER(x) ((x) >= 'a' && (x) <= 'z')
#endif

#ifndef ISALPHA
# define ISALPHA(x) (ISUPPER(x) || ISLOWER(x))
# endif


long
ft_strtol(const char *nptr, char **endptr, register int base)
{
        register const char *s = nptr;
        register unsigned long acc;
        register int c;
        register unsigned long cutoff;
        register int neg = 0, any, cutlim;
        /*
         * Skip white space and pick up leading +/- sign if any.
         * If base is 0, allow 0x for hex and 0 for octal, else
         * assume decimal; if base is already 16, allow 0x.
         */
        do {
                c = *s++;
        } while (ISSPACE(c));
        if (c == '-') {
                neg = 1;
                c = *s++;
        } else if (c == '+')
                c = *s++;
        if ((base == 0 || base == 16) &&
            c == '0' && (*s == 'x' || *s == 'X')) {
                c = s[1];
                s += 2;
                base = 16;
        }
        if (base == 0)
                base = c == '0' ? 8 : 10;
        /*
         * Compute the cutoff value between legal numbers and illegal
         * numbers.  That is the largest legal value, divided by the
         * base.  An input number that is greater than this value, if
         * followed by a legal input character, is too big.  One that
         * is equal to this value may be valid or not; the limit
         * between valid and invalid numbers is then based on the last
         * digit.  For instance, if the range for longs is
         * [-2147483648..2147483647] and the input base is 10,
         * cutoff will be set to 214748364 and cutlim to either
         * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
         * a value > 214748364, or equal but the next digit is > 7 (or 8),
         * the number is too big, and we will return a range error.
         *
         * Set any if any `digits' consumed; make it negative to indicate
         * overflow.
         */
        cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
        cutlim = cutoff % (unsigned long)base;
        cutoff /= (unsigned long)base;
        for (acc = 0, any = 0;; c = *s++) {
                if (ISDIGIT(c))
                        c -= '0';
                else if (ISALPHA(c))
                        c -= ISUPPER(c) ? 'A' - 10 : 'a' - 10;
                else
                        break;
                if (c >= base)
                        break;
                if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
                        any = -1;
                else {
                        any = 1;
                        acc *= base;
                        acc += c;
                }
        }
        if (any < 0) {
                acc = neg ? LONG_MIN : LONG_MAX;
                errno = ERANGE;
        } else if (neg)
                acc = -acc;
        if (endptr != 0)
                *endptr = (char *) (any ? s - 1 : nptr);
        return (acc);
}