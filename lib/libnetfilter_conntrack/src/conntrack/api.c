/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include <stdlib.h>
#include <string.h> /* for memset */
#include <errno.h>
#include <assert.h>

#include "internal.h"

/**
 * nfct_conntrack_new - allocate a new conntrack
 *
 * In case of success, this function returns a valid pointer to a memory blob,
 * otherwise NULL is returned and errno is set appropiately.
 */
struct nf_conntrack *nfct_new()
{
	struct nf_conntrack *ct;

	ct = malloc(sizeof(struct nf_conntrack));
	if (!ct)
		return NULL;

	memset(ct, 0, sizeof(struct nf_conntrack));

	return ct;
}

/**
 * nf_conntrack_destroy - release a conntrack object
 * @ct: pointer to the conntrack object
 */
void nfct_destroy(struct nf_conntrack *ct)
{
	assert(ct != NULL);
	free(ct);
	ct = NULL; /* bugtrap */
}

/**
 * nf_sizeof - return the size in bytes of a certain conntrack object
 * @ct: pointer to the conntrack object
 */
size_t nfct_sizeof(const struct nf_conntrack *ct)
{
	assert(ct != NULL);
	return sizeof(*ct);
}

/**
 * nfct_maxsize - return the maximum size in bytes of a conntrack object
 *
 * Use this function if you want to allocate a conntrack object in the stack
 * instead of the heap. For example:
 *
 * char buf[nfct_maxsize()];
 * struct nf_conntrack *ct = (struct nf_conntrack *) buf;
 * memset(ct, 0, nfct_maxsize());
 *
 * Note: As for now this function returns the same size that nfct_sizeof(ct)
 * does although _this could change in the future_. Therefore, do not assume
 * that nfct_sizeof(ct) == nfct_maxsize().
 */
size_t nfct_maxsize()
{
	return sizeof(struct nf_conntrack);
}

/**
 * nfct_clone - clone a conntrack object
 * @ct: pointer to a valid conntrack object
 *
 * On error, NULL is returned and errno is appropiately set. Otherwise,
 * a valid pointer to the clone conntrack is returned.
 */
struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
{
	struct nf_conntrack *clone;

	assert(ct != NULL);

	if ((clone = nfct_new()) == NULL)
		return NULL;
	memcpy(clone, ct, sizeof(*ct));

	return clone;
}

/**
 * nfct_setobjopt - set a certain option for a conntrack object
 * @ct: conntrack object
 * @option: option parameter
 *
 * In case of error, -1 is returned and errno is appropiately set. On success,
 * 0 is returned.
 */
int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)
{
	assert(ct != NULL);

	if (option > NFCT_SOPT_MAX) {
		errno = EOPNOTSUPP;
		return -1;
	}

	return __setobjopt(ct, option);
}

/**
 * nfct_getobjopt - get a certain option for a conntrack object
 * @ct: conntrack object
 * @option: option parameter
 *
 * In case of error, -1 is returned and errno is appropiately set. On success,
 * 0 is returned.
 */
int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)
{
	assert(ct != NULL);

	if (option > NFCT_GOPT_MAX) {
		errno = EOPNOTSUPP;
		return -1;
	}

	return __getobjopt(ct, option);
}

/**
 * nf_callback_register - register a callback
 * @h: library handler
 * @cb: callback used to process conntrack received
 * @data: data used by the callback, if any.
 *
 * This function register a callback to handle the conntrack received, 
 * in case of error -1 is returned and errno is set appropiately, otherwise
 * 0 is returned.
 *
 * Note that the data parameter is optional, if you do not want to pass any
 * data to your callback, then use NULL.
 */
int nfct_callback_register(struct nfct_handle *h,
			   enum nf_conntrack_msg_type type,
			   int (*cb)(enum nf_conntrack_msg_type type,
			   	     struct nf_conntrack *ct, 
				     void *data),
			   void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = malloc(sizeof(struct __data_container));
	if (!container)
		return -1;
	memset(container, 0, sizeof(struct __data_container));

	h->cb = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb.call = __callback;
	h->nfnl_cb.data = container;
	h->nfnl_cb.attr_count = CTA_MAX;

	nfnl_callback_register(h->nfnlssh_ct, 
			       IPCTNL_MSG_CT_NEW,
			       &h->nfnl_cb);

	nfnl_callback_register(h->nfnlssh_ct,
			       IPCTNL_MSG_CT_DELETE,
			       &h->nfnl_cb);

	return 0;
}

/**
 * nfct_callback_unregister - unregister a callback
 * @h: library handler
 */
void nfct_callback_unregister(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_NEW);
	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_DELETE);

	h->cb = NULL;
	free(h->nfnl_cb.data);

	h->nfnl_cb.call = NULL;
	h->nfnl_cb.data = NULL;
	h->nfnl_cb.attr_count = 0;
}

/**
 * nfct_set_attr - set the value of a certain conntrack attribute
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 * @value: pointer to the attribute value
 *
 * Note that certain attributes are unsettable:
 * 	- ATTR_USE
 * 	- ATTR_ID
 * 	- ATTR_*_COUNTER_*
 * The call of this function for such attributes do nothing.
 */
void nfct_set_attr(struct nf_conntrack *ct,
		   const enum nf_conntrack_attr type, 
		   const void *value)
{
	assert(ct != NULL);
	assert(value != NULL);

	if (type >= ATTR_MAX)
		return;

	if (set_attr_array[type]) {
		set_attr_array[type](ct, value);
		set_bit(type, ct->set);
	}
}

/**
 * nfct_set_attr_u8 - set the value of a certain conntrack attribute
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 * @value: unsigned 8 bits attribute value
 */
void nfct_set_attr_u8(struct nf_conntrack *ct,
		      const enum nf_conntrack_attr type, 
		      u_int8_t value)
{
	nfct_set_attr(ct, type, &value);
}

/**
 * nfct_set_attr_u16 - set the value of a certain conntrack attribute
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 * @value: unsigned 16 bits attribute value
 */
void nfct_set_attr_u16(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type, 
		       u_int16_t value)
{
	nfct_set_attr(ct, type, &value);
}

/**
 * nfct_set_attr_u32 - set the value of a certain conntrack attribute
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 * @value: unsigned 32 bits attribute value
 */
void nfct_set_attr_u32(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type, 
		       u_int32_t value)
{
	nfct_set_attr(ct, type, &value);
}

/**
 * nfct_set_attr_u64 - set the value of a certain conntrack attribute
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 * @value: unsigned 64 bits attribute value
 */
void nfct_set_attr_u64(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type,
		       u_int64_t value)
{
	nfct_set_attr(ct, type, &value);
}

/**
 * nfct_get_attr - get a conntrack attribute
 * ct: pointer to a valid conntrack
 * @type: attribute type
 *
 * In case of success a valid pointer to the attribute requested is returned,
 * on error NULL is returned and errno is set appropiately.
 */
const void *nfct_get_attr(const struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (type >= ATTR_MAX) {
		errno = EINVAL;
		return NULL;
	}

	if (!test_bit(type, ct->set)) {
		errno = ENODATA;
		return NULL;
	}

	return get_attr_array[type](ct);
}

/**
 * nfct_get_attr_u8 - get attribute of unsigned 8-bits long
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfct_attr_is_set.
 */
u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type)
{
	const u_int8_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfct_get_attr_u16 - get attribute of unsigned 16-bits long
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfct_attr_is_set.
 */
u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int16_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfct_get_attr_u32 - get attribute of unsigned 32-bits long
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfct_attr_is_set.
 */
u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int32_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfct_get_attr_u64 - get attribute of unsigned 64-bits long
 * @ct: pointer to a valid conntrack
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfct_attr_is_set.
 */
u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int64_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfct_attr_is_set - check if a certain attribute is set
 * @ct: pointer to a valid conntrack object
 * @type: attribute type
 *
 * On error, -1 is returned and errno is set appropiately, otherwise
 * the value of the attribute is returned.
 */
int nfct_attr_is_set(const struct nf_conntrack *ct,
		     const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (type >= ATTR_MAX) {
		errno = EINVAL;
		return -1;
	}
	return test_bit(type, ct->set);
}

/**
 * nfct_attr_unset - unset a certain attribute
 * @type: attribute type
 * @ct: pointer to a valid conntrack object
 * 
 * On error, -1 is returned and errno is set appropiately, otherwise
 * 0 is returned.
 */
int nfct_attr_unset(struct nf_conntrack *ct,
		    const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (type >= ATTR_MAX) {
		errno = EINVAL;
		return -1;
	}
	unset_bit(type, ct->set);

	return 0;
}

/**
 * nfct_build_conntrack - build a netlink message from a conntrack object
 * @ssh: nfnetlink subsystem handler
 * @req: buffer used to build the netlink message
 * @size: size of the buffer passed
 * @type: netlink message type
 * @flags: netlink flags
 * @ct: pointer to a conntrack object
 *
 * This is a low level function for those that require to be close to
 * netlink details via libnfnetlink. If you do want to obviate the netlink
 * details then we suggest you to use nfct_query.
 *
 * On error, -1 is returned and errno is appropiately set.
 * On success, 0 is returned.
 */
int nfct_build_conntrack(struct nfnl_subsys_handle *ssh,
			 void *req,
			 size_t size,
			 u_int16_t type,
			 u_int16_t flags,
			 const struct nf_conntrack *ct)
{
	assert(ssh != NULL);
	assert(req != NULL);
	assert(ct != NULL);

	return __build_conntrack(ssh, req, size, type, flags, ct);
}

/**
 * nfct_build_query - build a query in netlink message format for ctnetlink
 * @ssh: nfnetlink subsystem handler
 * @qt: query type
 * @data: data required to build the query
 * @req: buffer to build the netlink message
 * @size: size of the buffer passed
 *
 * This is a low level function, use it if you want to require to work
 * with netlink details via libnfnetlink, otherwise we suggest you to
 * use nfct_query.
 *
 * The pointer to data can be a conntrack object or the protocol family
 * depending on the request.
 *
 * For query types:
 * 	NFCT_Q_CREATE: add a new conntrack, if it exists, fail
 * 	NFCT_O_CREATE_UPDATE: add a new conntrack, if it exists, update it
 * 	NFCT_Q_UPDATE: update a conntrack
 * 	NFCT_Q_DESTROY: destroy a conntrack
 * 	NFCT_Q_GET: get a conntrack
 *
 * Pass a valid pointer to a conntrack object.
 *
 * For query types:
 * 	NFCT_Q_FLUSH: flush the conntrack table
 * 	NFCT_Q_DUMP: dump the conntrack table
 * 	NFCT_Q_DUMP_RESET: dump the conntrack table and reset counters
 *
 * Pass a valid pointer to the protocol family (u_int8_t)
 *
 * On success, 0 is returned. On error, -1 is returned and errno is set
 * appropiately.
 */
int nfct_build_query(struct nfnl_subsys_handle *ssh,
		     const enum nf_conntrack_query qt,
		     const void *data,
		     void *buffer,
		     unsigned int size)
{
	struct nfnlhdr *req = buffer;
	const u_int8_t *family = data;

	assert(ssh != NULL);
	assert(data != NULL);
	assert(req != NULL);

	memset(req, 0, size);

	switch(qt) {
	case NFCT_Q_CREATE:
		nfct_build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL, data);
		break;
	case NFCT_Q_UPDATE:
		nfct_build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_DESTROY:
		nfct_build_conntrack(ssh, req, size, IPCTNL_MSG_CT_DELETE, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_GET:
		nfct_build_conntrack(ssh, req, size, IPCTNL_MSG_CT_GET, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_FLUSH:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST|NLM_F_ACK);
		break;
	case NFCT_Q_DUMP:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_GET, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_DUMP);
		break;
	case NFCT_Q_DUMP_RESET:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_GET_CTRZERO, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_DUMP);
		break;
	case NFCT_Q_CREATE_UPDATE:
		nfct_build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK, data);
		break;

	default:
		errno = ENOTSUP;
		return -1;
	}
	return 1;
}

/**
 * nfct_parse_conntrack - translate a netlink message to a conntrack object
 * @type: do the translation iif the message type is of a certain type
 * @nlh: pointer to the netlink message
 * @ct: pointer to the conntrack object
 *
 * This is a low level function, use it in case that you require to work
 * with netlink details via libnfnetlink. Otherwise, we suggest you to
 * use the high level API.
 *
 * The message types are:
 *
 * NFCT_T_NEW: parse messages with new conntracks
 * NFCT_T_UPDATE: parse messages with conntrack updates
 * NFCT_T_DESTROY: parse messages with conntrack destroy 
 * NFCT_T_ALL: all message types
 *
 * The message type is a flag, therefore the can be combined, ie.
 * NFCT_T_NEW | NFCT_T_DESTROY to parse only new and destroy messages
 *
 * On error, NFCT_T_ERROR is returned and errno is set appropiately. If 
 * the message received is not of the requested type then 0 is returned, 
 * otherwise this function returns the message type parsed.
 */
int nfct_parse_conntrack(enum nf_conntrack_msg_type type,
			 const struct nlmsghdr *nlh,
			 struct nf_conntrack *ct)
{
	unsigned int flags;
	int len = nlh->nlmsg_len;
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_MAX];

	assert(nlh != NULL);
	assert(ct != NULL);

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0) {
		errno = EINVAL;
		return NFCT_T_ERROR;
	}

	flags = __parse_message_type(nlh);
	if (!(flags & type))
		return 0;

	nfnl_parse_attr(cda, CTA_MAX, NFA_DATA(nfhdr), len);

	__parse_conntrack(nlh, cda, ct);

	return flags;
}

/**
 * nfct_query - send a query to ctnetlin
 * @h: library handler
 * @qt: query type
 * @data: data required to send the query
 *
 * On error, -1 is returned and errno is explicitely set. On success, 0
 * is returned.
 */
int nfct_query(struct nfct_handle *h,
	       const enum nf_conntrack_query qt,
	       const void *data)
{
	size_t size = 4096;	/* enough for now */
	char buffer[4096];
	struct nfnlhdr *req = (struct nfnlhdr *) buffer;

	assert(h != NULL);
	assert(data != NULL);

	if (nfct_build_query(h->nfnlssh_ct, qt, data, req, size) == -1)
		return -1;

	return nfnl_query(h->nfnlh, &req->nlh);
}

/**
 * nfct_catch - catch events
 * @h: library handler
 *
 * On error, -1 is returned and errno is set appropiately. On success, 
 * a value greater or equal to 0 is returned indicating the callback
 * verdict: NFCT_CB_STOP, NFCT_CB_CONTINUE or NFCT_CB_STOLEN
 */
int nfct_catch(struct nfct_handle *h)
{
	assert(h != NULL);

	return nfnl_catch(h->nfnlh);
}

/**
 * nfct_snprintf - print a conntrack object to a buffer
 * @buf: buffer used to build the printable conntrack
 * @size: size of the buffer
 * @ct: pointer to a valid conntrack object
 * @message_type: print message type (NFCT_T_UNKNOWN, NFCT_T_NEW,...)
 * @output_type: print type (NFCT_O_DEFAULT, NFCT_O_XML, ...)
 * @flags: extra flags for the output type (NFCT_OF_LAYER3)
 *
 * If you are listening to events, probably you want to display the message 
 * type as well. In that case, set the message type parameter to any of the
 * known existing types, ie. NFCT_T_NEW, NFCT_T_UPDATE, NFCT_T_DESTROY.
 * If you pass NFCT_T_UNKNOWN, the message type will not be output. 
 *
 * Currently, the output available are:
 * 	- NFCT_O_DEFAULT: default /proc-like output
 * 	- NFCT_O_XML: XML output
 *
 * The output flags are:
 * 	- NFCT_O_LAYER: include layer 3 information in the output, this is
 * 			*only* required by NFCT_O_DEFAULT.
 *
 * This function returns the size of the information that _would_ have been 
 * written to the buffer, even if there was no room for it. Thus, the
 * behaviour is similar to snprintf.
 */
int nfct_snprintf(char *buf,
		  unsigned int size,
		  const struct nf_conntrack *ct,
		  unsigned int msg_type,
		  unsigned int out_type,
		  unsigned int flags) 
{
	assert(buf != NULL);
	assert(size > 0);
	assert(ct != NULL);

	return __snprintf_conntrack(buf, size, ct, msg_type, out_type, flags);
}

/**
 * nfct_compare - compare two conntrack objects
 * @ct1: pointer to a valid conntrack object
 * @ct2: pointer to a valid conntrack object
 *
 * This function only compare attribute set in both objects, ie. if a certain
 * attribute is not set in ct1 but it is in ct2, then the value of such 
 * attribute is not used in the comparison.
 *
 * If both conntrack object are equal, this function returns 1, otherwise
 * 0 is returned.
 */
int nfct_compare(const struct nf_conntrack *ct1, 
		 const struct nf_conntrack *ct2)
{
	assert(ct1 != NULL);
	assert(ct2 != NULL);

	return __compare(ct1, ct2);
}
