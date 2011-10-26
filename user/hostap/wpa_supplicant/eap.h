#ifndef EAP_H
#define EAP_H

#ifdef EAP_TLS_FUNCS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* EAP_TLS_FUNCS */

/* RFC 2284 - PPP Extensible Authentication Protocol (EAP) */

struct eap_hdr {
	u8 code;
	u8 identifier;
	u16 length; /* including code and identifier */
	/* followed by length-4 octets of data */
} __attribute__ ((packed));

enum { EAP_CODE_REQUEST = 1, EAP_CODE_RESPONSE = 2, EAP_CODE_SUCCESS = 3,
       EAP_CODE_FAILURE = 4 };

/* EAP Request and Response data begins with one octet Type. Success and
 * Failure do not have additional data. */

/* RFC 2284, 3.0 */
typedef enum {
	EAP_TYPE_NONE = 0,
	EAP_TYPE_IDENTITY = 1,
	EAP_TYPE_NOTIFICATION = 2,
	EAP_TYPE_NAK = 3 /* Response only */,
	EAP_TYPE_MD5 = 4,
	EAP_TYPE_OTP = 5 /* RFC 2284 */,
	EAP_TYPE_GTC = 6, /* RFC 2284 */
	EAP_TYPE_TLS = 13 /* RFC 2716 */,
	EAP_TYPE_LEAP = 17 /* Cisco proprietary */,
	EAP_TYPE_SIM = 18 /* draft-haverinen-pppext-eap-sim-12.txt */,
	EAP_TYPE_TTLS = 21 /* draft-ietf-pppext-eap-ttls-02.txt */,
	EAP_TYPE_PEAP = 25 /* draft-josefsson-pppext-eap-tls-eap-06.txt */,
	EAP_TYPE_MSCHAPV2 = 26 /* draft-kamath-pppext-eap-mschapv2-00.txt */,
	EAP_TYPE_TLV = 33 /* draft-josefsson-pppext-eap-tls-eap-07.txt */,
} EapType;


/* draft-ietf-eap-statemachine-02.pdf - Peer state machine */

struct eap_sm;

struct eap_method {
	EapType method;

	void * (*init)(struct eap_sm *sm);
	void (*deinit)(struct eap_sm *sm, void *priv);
	u8 * (*process)(struct eap_sm *sm, void *priv,
			u8 *reqData, size_t reqDataLen,
			size_t *respDataLen);
	Boolean (*isKeyAvailable)(struct eap_sm *sm, void *priv);
	u8 * (*getKey)(struct eap_sm *sm, void *priv, size_t *len);
};


struct eap_sm {
	enum {
		EAP_INITIALIZE, EAP_DISABLED, EAP_IDLE, EAP_RECEIVED,
		EAP_GET_METHOD, EAP_METHOD, EAP_SEND_RESPONSE, EAP_DISCARD,
		EAP_IDENTITY, EAP_NOTIFICATION, EAP_RETRANSMIT, EAP_SUCCESS,
		EAP_FAILURE
	} EAP_state;
	/* Long-term local variables */
	EapType selectedMethod;
	enum {
		METHOD_NONE, METHOD_INIT, METHOD_CONT, METHOD_MAY_CONT,
		METHOD_DONE
	} methodState;
	int lastId;
	u8 *lastRespData;
	size_t lastRespDataLen;
	enum {
		DECISION_FAIL, DECISION_COND_SUCC, DECISION_UNCOND_SUCC
	} decision;
	/* Short-term local variables */
	Boolean rxReq;
	Boolean rxSuccess;
	Boolean rxFailure;
	int reqId;
	EapType reqMethod;
	Boolean ignore;
	/* Constants */
	int ClientTimeout;

	/* Miscellaneous variables */
	Boolean allowNotifications; /* peer state machine <-> methods */
	u8 *eapRespData; /* peer to lower layer */
	size_t eapRespDataLen; /* peer to lower layer */
	Boolean eapKeyAvailable; /* peer to lower layer */
	u8 *eapKeyData; /* peer to lower layer */
	size_t eapKeyDataLen; /* peer to lower layer */
	const struct eap_method *m; /* selected EAP method */
	/* not defined in draft-ietf-eap-statemachine-02 */
	Boolean changed;
	struct eapol_sm *eapol;
	void *eap_method_priv;
	int init_phase2;

	Boolean rxResp /* LEAP only */;
	Boolean leap_done;
	Boolean peap_done;

#ifdef EAP_TLS_FUNCS
	SSL_CTX *ssl_ctx;
#endif /* EAP_TLS_FUNCS */
};


struct eap_sm *eap_sm_init(struct eapol_sm *eapol);
void eap_sm_deinit(struct eap_sm *sm);
int eap_sm_step(struct eap_sm *sm);
void eap_sm_abort(struct eap_sm *sm);
int eap_sm_get_status(struct eap_sm *sm, char *buf, size_t buflen);
u8 *eap_sm_buildIdentity(struct eap_sm *sm, int id, size_t *len,
			 int encrypted);
const struct eap_method * eap_sm_get_eap_methods(int method);
void eap_sm_request_identity(struct eap_sm *sm, struct wpa_ssid *config);
void eap_sm_request_password(struct eap_sm *sm, struct wpa_ssid *config);
void eap_sm_request_otp(struct eap_sm *sm, struct wpa_ssid *config,
			char *msg, size_t msg_len);
void eap_sm_notify_ctrl_attached(struct eap_sm *sm);

#endif /* EAP_H */
