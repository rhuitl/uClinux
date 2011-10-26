#ifndef UTIL_H
#define UTIL_H

#include <endian.h>
#include <byteswap.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le_to_host16(n) (n)
#define host_to_le16(n) (n)
#define be_to_host16(n) bswap_16(n)
#define host_to_be16(n) bswap_16(n)
#else
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#endif


#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#include "hostap_common.h"

void hostap_show_nicid(u8 *data, int len);
void hostap_show_priid(u8 *data, int len);
void hostap_show_staid(u8 *data, int len);
int hostapd_ioctl(const char *dev, struct prism2_hostapd_param *param,
		  int len, int show_err);
int hostapd_get_rid(const char *dev, struct prism2_hostapd_param *param,
		    u16 rid, int show_err);
int hostapd_set_rid(const char *dev, u16 rid, u8 *data, size_t len,
		    int show_err);
int hostap_ioctl_readmif(const char *dev, int cr);


#define PRISM2_PDA_SIZE 1024

struct prism2_pdr {
	unsigned int pdr, len;
	unsigned char *data;
};

struct prism2_pda {
	char pda_buf[PRISM2_PDA_SIZE];
	struct prism2_pdr *pdrs;
	int pdr_count;
};

int read_wlan_pda(const char *fname, struct prism2_pda *pda_info);
int read_wlan_pda_text(const char *fname, struct prism2_pda *pda_info);

#define PDR_PDA_END_RECORD 0x0000
#define PDR_PLATFORM_NAME 0x0001
#define PDR_VERSION 0x0002
#define PDR_NIC_SERIAL_NUM 0x0003
#define PDR_NIC_RAM_SIZE 0x0005
#define PDR_RF_MODE_SUPP_RANGE 0x0006
#define PDR_MAC_CTRL_SUPP_RANGE 0x0007
#define PDR_NIC_ID_COMP 0x0008
#define PDR_MAC_ADDR 0x0101
#define PDR_REG_DOMAIN_LIST 0x0103
#define PDR_CHANNEL_LIST 0x0104
#define PDR_DEFAULT_CHANNEL 0x0105
#define PDR_TEMPERATURE_TYPE 0x0107
#define PDR_IFR_SETTING 0x0200
#define PDR_RFR_SETTING 0x0201
#define PDR_3861_BASELINE_REG_SETTINGS 0x0202
#define PDR_3861_SHADOW_REG_SETTINGS 0x0203
#define PDR_3861_IFRF_REG_SETTINGS 0x0204
#define PDR_3861_CHANNEL_CALIB_SP 0x0300
#define PDR_3861_CHANNEL_CALIB_INT 0x0301
#define PDR_MAX_RADIO_TX_POWER 0x0302
#define PDR_MASTER_CHANNEL_LIST 0x0303
#define PDR_3842_NIC_CONF 0x0400
#define PDR_USB_ID 0x0401
#define PDR_PCI_ID 0x0402
#define PDR_PCI_INTERFACE_CONF 0x0403
#define PDR_PCI_PM_CONF 0x0404
#define PDR_ZIF_SYNTHESIZER_SETTINGS 0x0405
#define PDR_RSSI_DBM_CONV 0x0406
#define PDR_USB_POWER_TYPE 0x0407
#define PDR_USB_MAX_POWER 0x0409
#define PDR_USB_MANUF_STRING 0x0410
#define PDR_USB_PRODUCT_STRING 0x0411
#define PDR_SW_DIVERSITY_CTRL 0x0412
#define PDR_HFO_DELAY 0x0413
#define PDR_3861_MANUF_TEST_CHANNEL_SP 0x0900
#define PDR_MANUF_TEST_CHANNEL_INT 0x0901

struct pdr_supplier_range {
	u16 role;
	u16 iface_id;
	u16 variant;
	u16 bottom;
	u16 top;
} __attribute__((packed));


struct pdr_compid {
	u16 id;
	u16 variant;
	u16 major;
	u16 minor;
} __attribute__((packed));

const char * prism2_pdr_name(int pdr);

#endif /* UTIL_H */
