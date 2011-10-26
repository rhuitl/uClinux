/* string-lib.h - headers for string-lib.c
   $Id: string-lib.h,v 1.3 1997/01/21 07:18:02 eekim Exp $
*/

char *newstr(char *str);
char *substr(char *str, int offset, int len);
char *replace_ltgt(char *str);
char *lower_case(char *buffer);
