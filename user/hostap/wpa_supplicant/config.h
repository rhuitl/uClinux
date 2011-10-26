#ifndef CONFIG_H
#define CONFIG_H

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)

#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)

#define MAX_SSID_LEN 32
#define PMK_LEN 32

struct wpa_ssid {
	struct wpa_ssid *next; /* next network in global list */
	struct wpa_ssid *pnext; /* next network in per-priority list */
	int id; /* unique id for ctrl_iface */
	int priority;
	u8 *ssid;
	size_t ssid_len;
	u8 bssid[ETH_ALEN];
	int bssid_set;
	u8 psk[PMK_LEN];
	int psk_set;
	char *passphrase;
	/* Bitfields of allowed Pairwise/Group Ciphers, WPA_CIPHER_* */
	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int proto; /* Bitfield of allowed protocols (WPA_PROTO_*) */
	int scan_ssid; /* scan this SSID with Probe Requests */
	u8 *identity; /* EAP Identity */
	size_t identity_len;
	u8 *anonymous_identity; /* Anonymous EAP Identity (for unencrypted use
				 * with EAP types that support different
				 * tunnelled identity, e.g., EAP-TTLS) */
	size_t anonymous_identity_len;
	u8 *password;
	size_t password_len;
	u8 *ca_cert;
	u8 *client_cert;
	u8 *private_key;
	u8 *private_key_passwd;
	u8 *ca_cert2;
	u8 *client_cert2;
	u8 *private_key2;
	u8 *private_key2_passwd;
	u8 *eap_methods; /* zero (EAP_TYPE_NONE) terminated list of allowed
			  * EAP methods or NULL = any */
	char *phase1;
	char *phase2;
	char *pcsc;
	char *pin;

#define EAPOL_FLAG_REQUIRE_KEY_UNICAST BIT(0)
#define EAPOL_FLAG_REQUIRE_KEY_BROADCAST BIT(1)
	int eapol_flags; /* bit field of IEEE 802.1X/EAPOL options */

#define NUM_WEP_KEYS 4
#define MAX_WEP_KEY_LEN 16
	u8 wep_key[NUM_WEP_KEYS][MAX_WEP_KEY_LEN];
	size_t wep_key_len[NUM_WEP_KEYS];
	int wep_tx_keyidx;

	/* Per SSID variables that are not read from the configuration file */
	u8 *otp;
	size_t otp_len;
	int pending_req_identity, pending_req_password;
	u8 *pending_req_otp;
	size_t pending_req_otp_len;
	int leap, non_leap;
};


struct wpa_config {
	struct wpa_ssid *ssid; /* global network list */
	struct wpa_ssid **pssid; /* per priority network lists (in priority
				  * order) */
	int num_prio; /* number of different priorities */
	int eapol_version;
	int ap_scan;
	char *ctrl_interface; /* directory for UNIX domain sockets */
	gid_t ctrl_interface_gid;
};


struct wpa_config * wpa_config_read(const char *config_file);
void wpa_config_free(struct wpa_config *ssid);
int wpa_config_allowed_eap_method(struct wpa_ssid *ssid, int method);

#endif /* CONFIG_H */
