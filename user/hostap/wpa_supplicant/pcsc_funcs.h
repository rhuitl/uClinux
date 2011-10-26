#ifndef PCSC_FUNCS_H
#define PCSC_FUNCS_H

/* GSM files
 * File type in first octet:
 * 3F = Master File
 * 7F = Dedicated File
 * 2F = Elementary File under the Master File
 * 6F = Elementary File under a Dedicated File
 */
#define SCARD_FILE_MF		0x3F00
#define SCARD_FILE_GSM_DF	0x7F20
#define SCARD_FILE_UMTS_DF	0x7F50
#define SCARD_FILE_GSM_EF_IMSI	0x6F07
#define SCARD_FILE_EF_ICCID	0x2FE2

#define SCARD_CHV1_OFFSET	13
#define SCARD_CHV1_FLAG		0x80

typedef enum {
	SCARD_GSM_SIM_ONLY,
	SCARD_USIM_ONLY,
	SCARD_TRY_BOTH
} scard_sim_type;


#ifdef PCSC_FUNCS
struct scard_data * scard_init(scard_sim_type sim_type, char *pin);
void scard_deinit(struct scard_data *scard);

int scard_get_imsi(struct scard_data *scard, char *imsi, size_t *len);
int scard_gsm_auth(struct scard_data *scard, unsigned char *rand,
		   unsigned char *sres, unsigned char *kc);
int scard_select_file(struct scard_data *scard, unsigned short file_id,
		      unsigned char *buf, size_t *buf_len);
int scard_verify_pin(struct scard_data *scard, char *pin);

#else /* PCSC_FUNCS */

static inline struct scard_data * scard_init(scard_sim_type sim_type,
					     char *pin)
{
	return NULL;
}

static inline void scard_deinit(struct scard_data *scard)
{
}

static inline int scard_get_imsi(struct scard_data *scard, char *imsi,
				 size_t *len)
{
	return -1;
}

static inline int scard_gsm_auth(struct scard_data *scard, unsigned char *rand,
				 unsigned char *sres, unsigned char *kc)
{
	return -1;
}

static inline int scard_select_file(struct scard_data *scard,
				    unsigned short file_id,
				    unsigned char *buf, size_t *buf_len)
{
	return -1;
}

static inline int scard_verify_pin(struct scard_data *scard, char *pin)
{
	return -1;
}

#endif /* PCSC_FUNCS */

#endif /* PCSC_FUNCS_H */
