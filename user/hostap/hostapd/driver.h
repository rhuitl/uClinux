#ifndef DRIVER_H
#define DRIVER_H

struct hostap_sta_driver_data {
	unsigned long rx_packets, tx_packets, rx_bytes, tx_bytes;
};

struct hostap_driver_data {
	struct hostapd_data *hapd;

	char iface[IFNAMSIZ + 1];
	int sock; /* raw packet socket for driver access */
	int ioctl_sock; /* socket for ioctl() use */
	int wext_sock; /* socket for wireless events */
};


int hostapd_driver_init(struct hostapd_data *hapd);
void hostapd_driver_deinit(struct hostapd_data *hapd);
int hostapd_set_iface_flags(void *priv, int dev_up);
int hostapd_ioctl(void *priv, struct prism2_hostapd_param *param, int len);
int hostap_ioctl_prism2param(void *priv, int param, int value);
int hostap_ioctl_setiwessid(void *priv, char *buf, int len);
int hostapd_set_encryption(void *priv, const char *alg, u8 *addr,
			   int idx, u8 *key, size_t key_len);
int hostapd_get_seqnum(void *priv, u8 *addr, int idx, u8 *seq);
void remove_sta(void *priv, u8 *addr);
int hostapd_flush(void *priv);
int hostapd_read_sta_driver_data(void *priv,
				 struct hostap_sta_driver_data *data,
				 u8 *addr);
int hostapd_set_generic_elem(void *priv,
			     const char *elem, size_t elem_len);
int hostapd_wireless_event_init(void *priv);
void hostapd_wireless_event_deinit(void *priv);

/* receive.c */
int hostapd_init_sockets(struct hostap_driver_data *drv);

#endif /* DRIVER_H */
