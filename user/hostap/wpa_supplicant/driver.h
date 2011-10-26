#ifndef DRIVER_H
#define DRIVER_H

typedef enum { WPA_ALG_NONE, WPA_ALG_WEP, WPA_ALG_TKIP, WPA_ALG_CCMP } wpa_alg;
typedef enum { CIPHER_NONE, CIPHER_WEP40, CIPHER_TKIP, CIPHER_CCMP,
	       CIPHER_WEP104 } wpa_cipher;
typedef enum { KEY_MGMT_802_1X, KEY_MGMT_PSK, KEY_MGMT_NONE } wpa_key_mgmt;

#define AUTH_ALG_OPEN_SYSTEM	0x01
#define AUTH_ALG_SHARED_KEY	0x02
#define AUTH_ALG_LEAP		0x04

#define SSID_MAX_WPA_IE_LEN 40
struct wpa_scan_result {
	u8 bssid[ETH_ALEN];
	u8 ssid[32];
	size_t ssid_len;
	u8 wpa_ie[SSID_MAX_WPA_IE_LEN];
	size_t wpa_ie_len;
	u8 rsn_ie[SSID_MAX_WPA_IE_LEN];
	size_t rsn_ie_len;
	int freq; /* MHz */
	int caps; /* e.g. privacy */
	int qual; /* signal quality */
	int noise;
	int level;
	int maxrate;
};

struct wpa_driver_ops {
	/**
	 * get_bssid - get the current BSSID
	 * @ifname: interface name, e.g., wlan0
	 * @bssid: buffer for BSSID (ETH_ALEN = 6 bytes)
	 *
	 * Returns: 0 on success, -1 on failure
	 *
	 * Query kernel driver for the current BSSID and copy it to @bssid.
	 * Setting @bssid to 00:00:00:00:00:00 is recommended if the STA is not
	 * associated.
	 */
	int (*get_bssid)(const char *ifname, char *bssid);

	/**
	 * get_ssid - get the current SSID
	 * @ifname: interface name, e.g., wlan0
	 * @ssid: buffer for SSID (at least 32 bytes)
	 *
	 * Returns: length of the SSID on success, -1 on failure
	 *
	 * Query kernel driver for the current SSID and copy it to @ssid.
	 * Returning zero is recommended if the STA is not associated.
	 *
	 * Note: SSID is an array of octets, i.e., it is not nul terminated and
	 * can, at least in theory, contain control characters (including nul)
	 * and as such, should be processed as binary data, not a printable
	 * string.
	 */
	int (*get_ssid)(const char *ifname, char *ssid);

	/**
	 * set_wpa - enable/disable WPA support
	 * @ifname: interface name, e.g., wlan0
	 * @enabled: 1 = enable, 0 = disable
	 *
	 * Returns: 0 on success, -1 on failure
	 *
	 * Configure the kernel driver to enable/disable WPA support. This may
	 * be empty function, if WPA support is always enabled. Common
	 * configuration items are WPA IE (clearing it when WPA support is
	 * disabled), Privacy flag for capability field, roaming mode (need to
	 * allow wpa_supplicant to control roaming).
	 */
	int (*set_wpa)(const char *ifname, int enabled);

	/**
	 * set_key - configure encryption key
	 * @ifname: interface name, e.g., wlan0
	 * @alg: encryption algorithm (%WPA_ALG_NONE, %WPA_ALG_WEP,
	 *	%WPA_ALG_TKIP, %WPA_ALG_CCMP); %WPA_ALG_NONE clears the key.
	 * @addr: address of the peer STA or ff:ff:ff:ff:ff:ff for
	 *	broadcast/default keys
	 * @key_idx: key index (0..3), always 0 for unicast keys
	 * @set_tx: configure this key as the default Tx key (only used when
	 *	driver does not support separate unicast/individual key
	 * @seq: sequence number/packet number, @seq_len octets, the next
	 *	packet number to be used for in replay protection; configured
	 *	for Rx keys (in most cases, this is only used with broadcast
	 *	keys and set to zero for unicast keys)
	 * @seq_len: length of the @seq, depends on the algorithm:
	 *	TKIP: 6 octets, CCMP: 6 octets
	 * @key: key buffer; TKIP: 16-byte temporal key, 8-byte Tx Mic key,
	 *	8-byte Rx Mic Key
	 * @key_len: length of the key buffer in octets (WEP: 5 or 13,
	 *	TKIP: 32, CCMP: 16)
	 *
	 * Returns: 0 on success, -1 on failure
	 *
	 * Configure the given key for the kernel driver. If the driver
	 * supports separate individual keys (4 default keys + 1 individual),
	 * @addr can be used to determine whether the key is default or
	 * individual. If only 4 keys are supported, the default key with key
	 * index 0 is used as the individual key. STA must be configured to use
	 * it as the default Tx key (@set_tx is set) and accept Rx for all the
	 * key indexes. In most cases, WPA uses only key indexes 1 and 2 for
	 * broadcast keys, so key index 0 is available for this kind of
	 * configuration.
	 */
	int (*set_key)(const char *ifname, wpa_alg alg, u8 *addr,
		       int key_idx, int set_tx, u8 *seq, size_t seq_len,
		       u8 *key, size_t key_len);

	/**
	 * events_init - initialize processing of driver events
	 * @ctx: context to be used when calling wpa_supplicant_event()
	 *
	 * Return: pointer to private data, %NULL on failure
	 *
	 * Initialize event processing for kernel driver events (e.g.,
	 * associated, scan results, Michael MIC failure). This function can
	 * allocate a private configuration data area for file descriptor etc.
	 * information. If this is not used, non-NULL value will need to be
	 * returned because %NULL is used to indicate failure.
	 *
	 * The main event loop (eloop.c) of wpa_supplicant can be used to
	 * register callback for read sockets (eloop_register_read_sock()).
	 *
	 * See wpa_supplicant.h for more information about events and
	 * wpa_supplicant_event() function.
	 */
	void * (*events_init)(void *ctx);

	/**
	 * events_deinit - deinitialize processing of driver events
	 * @ctx: context to be used when calling wpa_supplicant_event() (same
	 *	as in matching wpa_driver_events_init() call)
	 * @priv: pointer to private data (from matching
	 *	wpa_driver_events_init())
	 *
	 * Return: 0 on success, -1 on failure
	 *
	 * Stop receiving kernel events. Free private data buffer if one was
	 * allocated in wpa_driver_events_init().
	 */
	int (*events_deinit)(void *ctx, void *priv);

	/**
	 * set_countermeasures - enable/disable TKIP countermeasures
	 * @ifname: interface name, e.g., wlan0
	 * @enabled: 1 = countermeasures enabled, 0 = disabled
	 *
	 * Return: 0 on success, -1 on failure
	 *
	 * Configure TKIP countermeasures. When these are enabled, the driver
	 * should drop all received and queued frames that are using TKIP.
	 */
	int (*set_countermeasures)(const char *ifname, int enabled);

	/**
	 * set_drop_unencrypted - enable/disable unencrypted frame filtering
	 * @ifname: interface name, e.g., wlan0
	 * @enabled: 1 = unencrypted Tx/Rx frames will be dropped, 0 = disabled
	 *
	 * Return: 0 on success, -1 on failure
	 *
	 * Configure the driver to drop all non-EAPOL frames (both receive and
	 * transmit paths). Unencrypted EAPOL frames (ethertype 0x888e) must
	 * still be allowed for key negotiation.
	 */
	int (*set_drop_unencrypted)(const char *ifname, int enabled);

	/**
	 * scan - request the driver to initiate scan
	 * @ifname: interface name, e.g., wlan0
	 * @ctx: context to be used when calling wpa_supplicant_event()
	 * @ssid: specific SSID to scan for (ProbeReq) or %NULL to scan for
	 *	all SSIDs (either active scan with broadcast SSID or passive
	 *	scan
	 * @ssid_len: length of the SSID
	 *
	 * Return: 0 on success, -1 on failure
	 *
	 * Once the scan results are ready, the driver should report scan
	 * results event for wpa_supplicant which will eventually request the
	 * results with wpa_driver_get_scan_results().
	 */
	int (*scan)(const char *ifname, void *ctx, u8 *ssid, size_t ssid_len);

	/**
	 * get_scan_results - fetch the latest scan results
	 * @ifname: interface name, e.g., wlan0
	 * @results: pointer to buffer for scan results
	 * @max_size: maximum number of entries (buffer size)
	 *
	 * Return: number of scan result entries used on success, -1 on failure
	 *
	 * If scan results include more than @max_size BSSes, @max_size will be
	 * returned and the remaining entries will not be included in the
	 * buffer.
	 */
	int (*get_scan_results)(const char *ifname,
				struct wpa_scan_result *results,
				size_t max_size);

	/**
	 * deauthenticate - request driver to deauthenticate
	 * @ifname: interface name, e.g., wlan0
	 * @addr: peer address (BSSID of the AP)
	 * @reason_code: 16-bit reason code to be sent in the deauthentication
	 *	frame
	 *
	 * Return: 0 on success, -1 on failure
	 */
	int (*deauthenticate)(const char *ifname, u8 *addr, int reason_code);

	/**
	 * disassociate - request driver to disassociate
	 * @ifname: interface name, e.g., wlan0
	 * @addr: peer address (BSSID of the AP)
	 * @reason_code: 16-bit reason code to be sent in the disassociation
	 *	frame
	 *
	 * Return: 0 on success, -1 on failure
	 */
	int (*disassociate)(const char *ifname, u8 *addr, int reason_code);

	/**
	 * associate - request driver to associate
	 * @ifname: interface name, e.g., wlan0
	 * @bssid: BSSID of the selected AP
	 * @ssid: the selected SSID
	 * @ssid_len: length of the SSID
	 * @freq: frequency that the selected AP is using (in MHz as reported
	 *	in the scan results)
	 * @wpa_ie: WPA information element to be included in (Re)Association
	 *	Request (including information element id and length). Use of
	 *	this WPA IE is optional. If the driver generates the WPA IE, it
	 *	can use @pairwise_suite, @group_suite, and @key_mgmt_suite
	 *	to select proper algorithms. In this case, the driver has to
	 *	notify wpa_supplicant about the used WPA IE by generating an
	 *	event that the interface code will convert into EVENT_ASSOCINFO
	 *	data (see wpa_supplicant.h). When using WPA2/IEEE 802.11i,
	 *	@wpa_ie is used for RSN IE instead. The driver can determine
	 *	which version is used by looking at the first byte of the IE
	 *	(0xdd for WPA, 0x30 for WPA2/RSN).
	 * @wpa_ie_len: length of the @wpa_ie
	 * @pairwise_suite: the selected pairwise cipher suite (this is usually
	 *	ignored if @wpa_ie is used)
	 * @group_suite: the selected group cipher suite (this is usually
	 *	ignored if @wpa_ie is used)
	 * @key_mgmt_suite: the selected key management suite (this is usually
	 *	ignored if @wpa_ie is used)
	 *
	 * Return: 0 on success, -1 on failure
	 */
	int (*associate)(const char *ifname, const char *bssid,
			 const char *ssid, size_t ssid_len, int freq,
			 const char *wpa_ie, size_t wpa_ie_len,
			 wpa_cipher pairwise_suite, wpa_cipher group_suite,
			 wpa_key_mgmt key_mgmt_suite);

	/**
	 * cleanup - cleanup driver state prior to exit
	 * @ifname: interface name, e.g., wlan0
	 *
	 * Return: nothing
	 */
	void (*cleanup)(const char *ifname);

	/**
	 * set_auth_alg - set IEEE 802.11 authentication algorithm
	 * @ifname: interface name, e.g., wlan0
	 * @auth_alg: bit field of AUTH_ALG_*
	 *
	 * If the driver supports more than one authentication algorithm at the
	 * same time, it should configure all supported algorithms. If not, one
	 * algorithm needs to be selected arbitrarily. Open System
	 * authentication should be ok for most cases and it is recommended to
	 * be used if other options are not supported. Static WEP configuration
	 * may also use Shared Key authentication and LEAP requires its own
	 * algorithm number. For LEAP, user can make sure that only one
	 * algorithm is used at a time by configuring LEAP as the only
	 * supported EAP method.
	 *
	 * Return: 0 on success, -1 on failure
	 */
	int (*set_auth_alg)(const char *ifname, int auth_alg);
};

#endif /* DRIVER_H */
