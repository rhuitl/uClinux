#ifndef _BYTE_EXTRACT_H
#define _BYTE_EXTRACT_H

#define BIG    0
#define LITTLE 1

#define PARSELEN 10

int string_extract(int bytes_to_grab, int base, u_int8_t *ptr,
                   u_int8_t *start, u_int8_t *end,
                   u_int32_t *value);

int byte_extract(int endianess, int bytes_to_grab, u_int8_t *ptr,
                 u_int8_t *start, u_int8_t *end,
                 u_int32_t *value);

#endif /* _BYTE_EXTRACT_H */
