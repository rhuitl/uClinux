#include "camconfig.h"
#include "camshm.h"
#include "databuf.h"
#include "filter.h"
#include "fixfont.h"
#include "font_6x11.h"
#include "font_8x8.h"
#include "grafxmisc.h"
#include "hash.h"
#include "jpgstuff.h"
#include "list.h"
#include "log.h"
#include "mainloop.h"
#include "manager.h"
#include "modinfo.h"
#include "picloop.h"
#include "socket.h"
#include "sock_field.h"
#include "sockset.h"
#include "video.h"

void *camserv_hack_databuf_buf_set = (void *)databuf_buf_set;
void *camserv_hack_databuf_dest = (void *)databuf_dest;
void *camserv_hack_databuf_new = (void *)databuf_new;
void *camserv_hack_databuf_read = (void *)databuf_read;
void *camserv_hack_databuf_write = (void *)databuf_write;
void *camserv_hack_camserv_get_pic_mean = (void *)camserv_get_pic_mean;
void *camserv_hack_camserv_get_pic_stddev = (void *)camserv_get_pic_stddev;
void *camserv_hack_hash_alloc_insert = (void *)hash_alloc_insert;
void *camserv_hack_hash_count = (void *)hash_count;
void *camserv_hack_hash_create = (void *)hash_create;
void *camserv_hack_hash_delete = (void *)hash_delete;
void *camserv_hack_hash_delete_free = (void *)hash_delete_free;
void *camserv_hack_hash_destroy = (void *)hash_destroy;
void *camserv_hack_hash_free = (void *)hash_free;
void *camserv_hack_hash_init = (void *)hash_init;
void *camserv_hack_hash_insert = (void *)hash_insert;
void *camserv_hack_hash_isempty = (void *)hash_isempty;
void *camserv_hack_hash_isfull = (void *)hash_isfull;
void *camserv_hack_hash_lookup = (void *)hash_lookup;
void *camserv_hack_hash_scan_begin = (void *)hash_scan_begin;
void *camserv_hack_hash_scan_delete = (void *)hash_scan_delete;
void *camserv_hack_hash_scan_next = (void *)hash_scan_next;
void *camserv_hack_hash_set_allocator = (void *)hash_set_allocator;
void *camserv_hack_hash_size = (void *)hash_size;
void *camserv_hack_hash_verify = (void *)hash_verify;
void *camserv_hack_hnode_create = (void *)hnode_create;
void *camserv_hack_hnode_destroy = (void *)hnode_destroy;
void *camserv_hack_hnode_get = (void *)hnode_get;
void *camserv_hack_hnode_getkey = (void *)hnode_getkey;
void *camserv_hack_hnode_init = (void *)hnode_init;
void *camserv_hack_hnode_put = (void *)hnode_put;
void *camserv_hack_list_append = (void *)list_append;
void *camserv_hack_list_contains = (void *)list_contains;
void *camserv_hack_list_count = (void *)list_count;
void *camserv_hack_list_create = (void *)list_create;
void *camserv_hack_list_del_first = (void *)list_del_first;
void *camserv_hack_list_del_last = (void *)list_del_last;
void *camserv_hack_list_delete = (void *)list_delete;
void *camserv_hack_list_destroy = (void *)list_destroy;
void *camserv_hack_list_destroy_nodes = (void *)list_destroy_nodes;
void *camserv_hack_list_extract = (void *)list_extract;
void *camserv_hack_list_first = (void *)list_first;
void *camserv_hack_list_init = (void *)list_init;
void *camserv_hack_list_ins_after = (void *)list_ins_after;
void *camserv_hack_list_ins_before = (void *)list_ins_before;
void *camserv_hack_list_is_sorted = (void *)list_is_sorted;
void *camserv_hack_list_isempty = (void *)list_isempty;
void *camserv_hack_list_isfull = (void *)list_isfull;
void *camserv_hack_list_last = (void *)list_last;
void *camserv_hack_list_merge = (void *)list_merge;
void *camserv_hack_list_next = (void *)list_next;
void *camserv_hack_list_prepend = (void *)list_prepend;
void *camserv_hack_list_prev = (void *)list_prev;
void *camserv_hack_list_process = (void *)list_process;
void *camserv_hack_list_return_nodes = (void *)list_return_nodes;
void *camserv_hack_list_sort = (void *)list_sort;
void *camserv_hack_list_transfer = (void *)list_transfer;
void *camserv_hack_list_verify = (void *)list_verify;
void *camserv_hack_lnode_borrow = (void *)lnode_borrow;
void *camserv_hack_lnode_create = (void *)lnode_create;
void *camserv_hack_lnode_destroy = (void *)lnode_destroy;
void *camserv_hack_lnode_get = (void *)lnode_get;
void *camserv_hack_lnode_init = (void *)lnode_init;
void *camserv_hack_lnode_is_in_a_list = (void *)lnode_is_in_a_list;
void *camserv_hack_lnode_pool_create = (void *)lnode_pool_create;
void *camserv_hack_lnode_pool_destroy = (void *)lnode_pool_destroy;
void *camserv_hack_lnode_pool_init = (void *)lnode_pool_init;
void *camserv_hack_lnode_pool_isempty = (void *)lnode_pool_isempty;
void *camserv_hack_lnode_pool_isfrom = (void *)lnode_pool_isfrom;
void *camserv_hack_lnode_put = (void *)lnode_put;
void *camserv_hack_lnode_return = (void *)lnode_return;
void *camserv_hack_camserv_log = (void *)camserv_log;
void *camserv_hack_manager_dest_client = (void *)manager_dest_client;
void *camserv_hack_manager_new_client = (void *)manager_new_client;
void *camserv_hack_manager_new_picture = (void *)manager_new_picture;
void *camserv_hack_modinfo_create = (void *)modinfo_create;
void *camserv_hack_modinfo_desc_set = (void *)modinfo_desc_set;
void *camserv_hack_modinfo_destroy = (void *)modinfo_destroy;
void *camserv_hack_modinfo_dump = (void *)modinfo_dump;
void *camserv_hack_modinfo_query_so = (void *)modinfo_query_so;
void *camserv_hack_modinfo_varname_set = (void *)modinfo_varname_set;
void *camserv_hack_socket_accept = (void *)socket_accept;
void *camserv_hack_socket_connect = (void *)socket_connect;
void *camserv_hack_socket_dest = (void *)socket_dest;
void *camserv_hack_socket_new = (void *)socket_new;
void *camserv_hack_socket_query_fd = (void *)socket_query_fd;
void *camserv_hack_socket_query_remote_name = (void *)socket_query_remote_name;
void *camserv_hack_socket_serve_tcp = (void *)socket_serve_tcp;
void *camserv_hack_socket_set_nonblock = (void *)socket_set_nonblock;
void *camserv_hack_socket_unix_pair = (void *)socket_unix_pair;
void *camserv_hack_socket_unix_pair_dest = (void *)socket_unix_pair_dest;
void *camserv_hack_socket_zero = (void *)socket_zero;
void *camserv_hack_sockset_add_fd = (void *)sockset_add_fd;
void *camserv_hack_sockset_del_fd = (void *)sockset_del_fd;
void *camserv_hack_sockset_dest = (void *)sockset_dest;
void *camserv_hack_sockset_hold = (void *)sockset_hold;
void *camserv_hack_sockset_new = (void *)sockset_new;
void *camserv_hack_sockset_query_nsocks = (void *)sockset_query_nsocks;
void *camserv_hack_sockset_query_socks = (void *)sockset_query_socks;
void *camserv_hack_sockset_reset = (void *)sockset_reset;
void *camserv_hack_sockset_select = (void *)sockset_select;
void *camserv_hack_sockset_unhold_all = (void *)sockset_unhold_all;
void *camserv_hack_sock_field = (void *)sock_field;
void *camserv_hack_sock_field_hold_write = (void *)sock_field_hold_write;
void *camserv_hack_sock_field_manage_socket = (void *)sock_field_manage_socket;
void *camserv_hack_sock_field_unhold_write = (void *)sock_field_unhold_write;
