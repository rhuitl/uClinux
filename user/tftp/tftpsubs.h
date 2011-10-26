int synchnet(int);
struct tftphdr *r_init(void);
struct tftphdr *w_init(void);
int readit(FILE *file, struct tftphdr **dpp, int convert);
int writeit(FILE *file, struct tftphdr **dpp, int ct, int convert);
void read_ahead(FILE *file, int convert /* if true, convert to ascii */);
int write_behind(FILE *file, int convert);
