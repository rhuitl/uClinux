/*
 * Copyright 1996-2000 Hans Reiser
 */

/* nothing abount reiserfs here */

void die (char * fmt, ...);
void * getmem (int size);
void freemem (void * p);
void checkmem (char * p, int size);
void * expandmem (void * p, int size, int by);
int is_mounted (char * device_name);
int is_mounted_read_only (char * device_name);
void check_and_free_mem (void);
char * kdevname (int dev);


int set_bit (int nr, void * addr);
int clear_bit (int nr, void * addr);
int test_bit(int nr, const void * addr);
int find_first_zero_bit (const void *vaddr, unsigned size);
int find_next_zero_bit (const void *vaddr, unsigned size, unsigned offset);

void print_how_far (unsigned long * passed, unsigned long total, int inc, int quiet);
void print_how_fast (unsigned long total, 
		     unsigned long passed, int cursor_pos);
int user_confirmed (char * q, char * yes);


/*
int test_and_set_bit (int nr, void * addr);
int test_and_clear_bit (int nr, void * addr);
*/
inline __u32 cpu_to_le32 (__u32 val);
inline __u32 le32_to_cpu (__u32 val);
inline __u16 cpu_to_le16 (__u16 val);
inline __u16 le16_to_cpu (__u16 val);
inline __u64 cpu_to_le64 (__u64 val);
inline __u64 le64_to_cpu (__u64 val);

unsigned long count_blocks (char * filename, int blocksize, int fd);

