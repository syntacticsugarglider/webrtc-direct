#include <stdio.h>
#include <stdarg.h>

void variadic_debug(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
};