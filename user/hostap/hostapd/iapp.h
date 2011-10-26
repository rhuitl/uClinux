#ifndef IAPP_H
#define IAPP_H

#define IAPP_PORT 2313 /* To be decided */

struct iapp_hdr {
	u8 version;
	u8 command;
	u16 identifier;
	u16 length;
	/* followed by length-6 octets of data */
} __attribute__ ((packed));

#define IAPP_VERSION 0

enum IAPP_COMMAND {
	IAPP_CMD_ADD_notify = 0,
	IAPP_CMD_MOVE_notify = 1,
	IAPP_CMD_MOVE_response = 2,
	IAPP_CMD_Send_Security_Block = 3,
	IAPP_CMD_ACK_Security_Block = 4
};

struct iapp_add_notify {
	u8 addr_len;
	u8 reserved;
	u8 mac_addr[6];
	u16 seq_num;
} __attribute__ ((packed));


/* Layer 2 Update frame (802.2 Type 1 LLC XID Update response) */
struct iapp_layer2_update {
	u8 da[6]; /* broadcast */
	u8 sa[6]; /* STA addr */
	u16 len; /* 8 */
	u8 dsap; /* 0 */
	u8 ssap; /* 0 */
	u8 control;
	u8 xid_info[3];
};


void iapp_new_station(hostapd *hapd, struct sta_info *sta);
int iapp_init(hostapd *hapd);
void iapp_deinit(hostapd *hapd);

#endif /* IAPP_H */
