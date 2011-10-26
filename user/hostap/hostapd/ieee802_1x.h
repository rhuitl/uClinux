#ifndef IEEE802_1X_H
#define IEEE802_1X_H

/* IEEE Std 802.1X-2001, 7.2 */

struct ieee802_1x_hdr {
	u8 version;
	u8 type;
	u16 length;
	/* followed by length octets of data */
} __attribute__ ((packed));

#define EAPOL_VERSION 1

enum { IEEE802_1X_TYPE_EAP_PACKET = 0,
       IEEE802_1X_TYPE_EAPOL_START = 1,
       IEEE802_1X_TYPE_EAPOL_LOGOFF = 2,
       IEEE802_1X_TYPE_EAPOL_KEY = 3,
       IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT = 4
};

/* draft-congdon-radius-8021x-20.txt */

struct ieee802_1x_eapol_key {
	u8 type;
	u16 key_length;
	u8 replay_counter[8]; /* does not repeat within the life of the keying
			       * material used to encrypt the Key field;
			       * 64-bit NTP timestamp MAY be used here */
	u8 key_iv[16]; /* cryptographically random number */
	u8 key_index; /* key flag in the most significant bit:
		       * 0 = broadcast (default key),
		       * 1 = unicast (key mapping key); key index is in the
		       * 7 least significant bits */
	u8 key_signature[16]; /* HMAC-MD5 message integrity check computed with
			       * MS-MPPE-Send-Key as the key */

	/* followed by key: if packet body length = 44 + key length, then the
	 * key field (of key_length bytes) contains the key in encrypted form;
	 * if packet body length = 44, key field is absent and key_length
	 * represents the number of least significant octets from
	 * MS-MPPE-Send-Key attribute to be used as the keying material;
	 * RC4 key used in encryption = Key-IV + MS-MPPE-Recv-Key */
} __attribute__ ((packed));

enum { EAPOL_KEY_TYPE_RC4 = 1, EAPOL_KEY_TYPE_RSN = 2,
       EAPOL_KEY_TYPE_WPA = 254 };


/* RFC 2284 - PPP Extensible Authentication Protocol (EAP) */

struct eap_hdr {
	u8 code;
	u8 identifier;
	u16 length; /* including code and identifier */
	/* followed by length-2 octets of data */
} __attribute__ ((packed));

enum { EAP_CODE_REQUEST = 1, EAP_CODE_RESPONSE = 2, EAP_CODE_SUCCESS = 3,
       EAP_CODE_FAILURE = 4 };

/* EAP Request and Response data begins with one octet Type. Success and
 * Failure do not have additional data. */

/* RFC 2284, 3.0 */
enum { EAP_TYPE_IDENTITY = 1,
       EAP_TYPE_NOTIFICATION = 2,
       EAP_TYPE_NAK = 3 /* Response only */,
       EAP_TYPE_MD5_CHALLENGE = 4,
       EAP_TYPE_ONE_TIME_PASSWORD = 5 /* RFC 1938 */,
       EAP_TYPE_GENERIC_TOKEN_CARD = 6,
       EAP_TYPE_TLS = 13 /* RFC 2716 */,
       EAP_TYPE_TTLS = 21 /* draft-ietf-pppext-eap-ttls-02.txt */,
       EAP_TYPE_PEAP = 25 /* draft-josefsson-pppext-eap-tls-eap-06.txt */,
};


void ieee802_1x_receive(hostapd *hapd, u8 *sa, u8 *buf, size_t len);
void ieee802_1x_new_station(hostapd *hapd, struct sta_info *sta);
void ieee802_1x_free_station(struct sta_info *sta);

void ieee802_1x_request_identity(hostapd *hapd, struct sta_info *sta, u8 id);
void ieee802_1x_tx_canned_eap(hostapd *hapd, struct sta_info *sta, u8 id,
			      int success);
void ieee802_1x_tx_req(hostapd *hapd, struct sta_info *sta, u8 id);
void ieee802_1x_tx_key(hostapd *hapd, struct sta_info *sta, u8 id);
void ieee802_1x_send_resp_to_server(hostapd *hapd, struct sta_info *sta);
void ieee802_1x_set_sta_authorized(hostapd *hapd, struct sta_info *sta,
				   int authorized);
void ieee802_1x_set_port_enabled(hostapd *hapd, struct sta_info *sta,
				 int enabled);
void ieee802_1x_dump_state(FILE *f, const char *prefix, struct sta_info *sta);
int ieee802_1x_init(hostapd *hapd);
void ieee802_1x_deinit(hostapd *hapd);
void ieee802_1x_new_auth_session(hostapd *hapd, struct sta_info *sta);
int ieee802_1x_tx_status(hostapd *hapd, struct sta_info *sta, u8 *buf,
			 size_t len, int ack);
u8 * ieee802_1x_get_identity(struct eapol_state_machine *sm, size_t *len);
u8 * ieee802_1x_get_radius_class(struct eapol_state_machine *sm, size_t *len);
u8 * ieee802_1x_get_key_crypt(struct eapol_state_machine *sm, size_t *len);
void ieee802_1x_notify_port_enabled(struct eapol_state_machine *sm,
				    int enabled);
void ieee802_1x_notify_port_valid(struct eapol_state_machine *sm,
				  int valid);
void ieee802_1x_notify_key_available(struct eapol_state_machine *sm,
				     int available);
void ieee802_1x_notify_pre_auth(struct eapol_state_machine *sm, int pre_auth);

#endif /* IEEE802_1X_H */
