#ifndef MANAGER_DOT_H
#define MANAGER_DOT_H

extern void *manager_new_client( char **pic_data, 
				 size_t *pic_size, int *pic_id );
extern int manager_dest_client( void *reset_data );

extern int manager_new_picture( char *picture_data, size_t pic_size, 
				int max_clients );

#endif
