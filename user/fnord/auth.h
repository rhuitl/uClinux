#ifndef AUTH_H
#define AUTH_H

extern int auth_fallback;

void auth_add(char *directory,char *file);
void auth_check(void);
int auth_authorize(const char *host, const char *url, const char *remote_ip_addr, const char *authorization, char username[15], char id[15]);
void dump_auth(void);

#endif
