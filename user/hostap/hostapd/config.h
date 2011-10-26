#ifndef CONFIG_H
#define CONFIG_H

typedef u8 macaddr[ETH_ALEN];

struct hostapd_radius_server {
	struct in_addr addr;
	int port;
	u8 *shared_secret;
	size_t shared_secret_len;
};

struct hostapd_config {
	char iface[IFNAMSIZ + 1];

	enum {
		HOSTAPD_LEVEL_DEBUG_VERBOSE = 0,
		HOSTAPD_LEVEL_DEBUG = 1,
		HOSTAPD_LEVEL_INFO = 2,
		HOSTAPD_LEVEL_NOTICE = 3,
		HOSTAPD_LEVEL_WARNING = 4
	} logger_syslog_level, logger_stdout_level;

#define HOSTAPD_MODULE_IEEE80211 BIT(0)
#define HOSTAPD_MODULE_IEEE8021X BIT(1)
#define HOSTAPD_MODULE_RADIUS BIT(2)
#define HOSTAPD_MODULE_WPA BIT(3)
	unsigned int logger_syslog; /* module bitfield */
	unsigned int logger_stdout; /* module bitfield */

	enum { HOSTAPD_DEBUG_NO = 0, HOSTAPD_DEBUG_MINIMAL = 1,
	       HOSTAPD_DEBUG_VERBOSE = 2,
	       HOSTAPD_DEBUG_MSGDUMPS = 3,
	       HOSTAPD_DEBUG_EXCESSIVE = 4 } debug; /* debug verbosity level */
	char *dump_log_name; /* file name for state dump (SIGUSR1) */
	int daemonize; /* fork into background */

	int ieee802_1x; /* use IEEE 802.1X */
	int minimal_eap; /* test version of EAP authentication that only
			  * requires EAP Response-Identity and authorizes any
			  * station */
	struct in_addr own_ip_addr;
	char *nas_identifier;
	/* RADIUS Authentication and Accounting servers in priority order */
	struct hostapd_radius_server *auth_servers, *auth_server;
	int num_auth_servers;
	struct hostapd_radius_server *acct_servers, *acct_server;
	int num_acct_servers;

	int radius_retry_primary_interval;
	int radius_acct_interim_interval;
#define HOSTAPD_SSID_LEN 32
	char ssid[HOSTAPD_SSID_LEN + 1];
	size_t ssid_len;
	char *eap_req_id_text; /* optional displayable message sent with
				* EAP Request-Identity */
	int eapol_key_index_workaround;

	size_t default_wep_key_len;
	int individual_wep_key_len;
	int wep_rekeying_period;

	int ieee802_11f; /* use IEEE 802.11f (IAPP) */
	char iapp_iface[IFNAMSIZ + 1]; /* interface used with IAPP broadcast
					* frames */

	u8 assoc_ap_addr[ETH_ALEN];
	int assoc_ap; /* whether assoc_ap_addr is set */

	enum {
		ACCEPT_UNLESS_DENIED = 0,
		DENY_UNLESS_ACCEPTED = 1,
		USE_EXTERNAL_RADIUS_AUTH = 2
	} macaddr_acl;
	macaddr *accept_mac;
	int num_accept_mac;
	macaddr *deny_mac;
	int num_deny_mac;

#define HOSTAPD_AUTH_OPEN BIT(0)
#define HOSTAPD_AUTH_SHARED_KEY BIT(1)
	int auth_algs; /* bitfield of allowed IEEE 802.11 authentication
			* algorithms */

#define HOSTAPD_WPA_VERSION_WPA BIT(0)
#define HOSTAPD_WPA_VERSION_WPA2 BIT(1)
	int wpa;
#define PMK_LEN 32
	u8 *wpa_psk;
	char *wpa_passphrase;
#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
	int wpa_key_mgmt;
#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)
	int wpa_pairwise;
	int wpa_group;
	int wpa_group_rekey;
	int wpa_gmk_rekey;
	int rsn_preauth;
	char *rsn_preauth_interfaces;
};


struct hostapd_config * hostapd_config_read(const char *fname);
void hostapd_config_free(struct hostapd_config *conf);
int hostapd_maclist_found(macaddr *list, int num_entries, u8 *addr);


#endif /* CONFIG_H */
