#ifndef DRIVER_WEXT_H
#define DRIVER_WEXT_H

int wpa_driver_wext_get_bssid(const char *ifname, char *bssid);
int wpa_driver_wext_set_bssid(const char *ifname, const char *bssid);
int wpa_driver_wext_get_ssid(const char *ifname, char *ssid);
int wpa_driver_wext_get_ssid(const char *ifname, char *ssid);
int wpa_driver_wext_set_ssid(const char *ifname, const char *ssid,
			     size_t ssid_len);
int wpa_driver_wext_set_freq(const char *ifname, int freq);
void * wpa_driver_wext_events_init(void *ctx);
int wpa_driver_wext_events_deinit(void *ctx, void *priv);
int wpa_driver_wext_scan(const char *ifname, void *ctx, u8 *ssid,
			 size_t ssid_len);
int wpa_driver_wext_get_scan_results(const char *ifname,
				     struct wpa_scan_result *results,
				     size_t max_size);

void wpa_driver_wext_scan_timeout(void *eloop_ctx, void *timeout_ctx);

#endif /* DRIVER_WEXT_H */
