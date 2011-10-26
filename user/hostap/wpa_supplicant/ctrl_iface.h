#ifndef CTRL_IFACE_H
#define CTRL_IFACE_H

void wpa_supplicant_ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx);
int wpa_supplicant_ctrl_iface_init(struct wpa_supplicant *wpa_s);
void wpa_supplicant_ctrl_iface_deinit(struct wpa_supplicant *wpa_s);
void wpa_supplicant_ctrl_iface_send(struct wpa_supplicant *wpa_s, int level,
				    char *buf, size_t len);

#endif /* CTRL_IFACE_H */
