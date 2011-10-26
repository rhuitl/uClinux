struct buffer_head {
  unsigned long b_blocknr;
  unsigned short b_dev;
  unsigned long b_size;
  char * b_data;
  unsigned long b_state;
  unsigned int b_count;
  unsigned int b_list ;
  void (*b_end_io)(struct buffer_head *bh, int uptodate);

  struct buffer_head * b_next;
  struct buffer_head * b_prev;
  struct buffer_head * b_hash_next;
  struct buffer_head * b_hash_prev;
};

#define BH_Uptodate	0
#define BH_Dirty	1
#define BH_Lock		2


#define buffer_uptodate(bh) test_bit(BH_Uptodate, &(bh)->b_state)
#define buffer_dirty(bh) test_bit(BH_Dirty, &(bh)->b_state)
#define buffer_locked(bh) test_bit(BH_Lock, &(bh)->b_state)
#define buffer_clean(bh) !test_bit(BH_Dirty, &(bh)->b_state)
#define mark_buffer_dirty(bh) set_bit(BH_Dirty, &(bh)->b_state)
/*
printf ("%s:%s:%u %p %p %p\n", 
__FILE__, __FUNCTION__, __LINE__,
	__builtin_return_address (0),
	__builtin_return_address (1),
	__builtin_return_address (2));
*/

#define mark_buffer_uptodate(bh,i) set_bit(BH_Uptodate, &(bh)->b_state)
#define mark_buffer_clean(bh) clear_bit(BH_Dirty, &(bh)->b_state)


void __wait_on_buffer (struct buffer_head * bh);
struct buffer_head * getblk (int dev, int block, int size);
struct buffer_head * reiserfs_getblk (int dev, int block, int size, int *repeat);

struct buffer_head * find_buffer (int dev, int block, int size);
struct buffer_head * get_hash_table(dev_t dev, int block, int size);
struct buffer_head * bread (int dev, unsigned long block, size_t size);
struct buffer_head * reiserfs_bread (int dev, int block, int size, int *repeat);
int valid_offset (int fd, loff_t offset);
int bwrite (struct buffer_head * bh);
void brelse (struct buffer_head * bh);
void bforget (struct buffer_head * bh);
void check_and_free_buffer_mem (void);

void flush_buffers (void);
void free_buffers (void);

loff_t reiserfs_llseek (unsigned int fd, loff_t offset, unsigned int origin);

