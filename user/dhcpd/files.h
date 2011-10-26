/* files.h */

int search_config_file(char *filename, char *keyword, char *value);
int addLeased(u_int32_t yiaddr, u_int8_t chaddr[16]);
int check_if_already_leased(u_int32_t yiaddr, u_int8_t chaddr[16]);
int get_multiple_entries(char *hay, char *needle, char *tmp1, char *tmp2, char *tmp3);

