/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 * nfexp_new - allocate a new expectation
 *
 * In case of success, this function returns a valid pointer to a memory blob,
 * otherwise NULL is returned and errno is set appropiately.
 */
struct nf_expect *nfexp_new()
{
	struct nf_expect *exp;

	exp = malloc(sizeof(struct nf_expect));
	if (!exp)
		return NULL;

	memset(exp, 0, sizeof(struct nf_expect));

	return exp;
}

/**
 * nfexp_destroy - release an expectation object
 * @exp: pointer to the expectation object
 */
void nfexp_destroy(struct nf_expect *exp)
{
	assert(exp != NULL);
	free(exp);
	exp = NULL; /* bugtrap */
}

/**
 * nfexp_sizeof - return the size in bytes of a certain expect object
 * @exp: pointer to the expect object
 */
size_t nfexp_sizeof(const struct nf_expect *exp)
{
	assert(exp != NULL);
	return sizeof(*exp);
}

/**
 * nfexp_maxsize - return the maximum size in bytes of a expect object
 *
 * Use this function if you want to allocate a expect object in the stack
 * instead of the heap. For example:
 *
 * char buf[nfexp_maxsize()];
 * struct nf_expect *exp = (struct nf_expect *) buf;
 * memset(exp, 0, nfexp_maxsize());
 *
 * Note: As for now this function returns the same size that nfexp_sizeof(exp)
 * does although _this could change in the future_. Therefore, do not assume
 * that nfexp_sizeof(exp) == nfexp_maxsize().
 */
size_t nfexp_maxsize()
{
	return sizeof(struct nf_expect);
}

/**
 * nfexp_clone - clone a expectation object
 * @exp: pointer to a valid expectation object
 *
 * On error, NULL is returned and errno is appropiately set. Otherwise,
 * a valid pointer to the clone expect is returned.
 */
struct nf_expect *nfexp_clone(const struct nf_expect *exp)
{
	struct nf_expect *clone;

	assert(exp != NULL);

	if ((clone = nfexp_new()) == NULL)
		return NULL;
	memcpy(clone, exp, sizeof(*exp));

	return clone;
}

/**
 * nfexp_callback_register - register a callback
 * @h: library handler
 * @cb: callback used to process expect received
 * @data: data used by the callback, if any.
 *
 * This function register a callback to handle the expect received, 
 * in case of error -1 is returned and errno is set appropiately, otherwise
 * 0 is returned.
 *
 * Note that the data parameter is optional, if you do not want to pass any
 * data to your callback, then use NULL.
 */
int nfexp_callback_register(struct nfct_handle *h,
			    enum nf_conntrack_msg_type type,
			    int (*cb)(enum nf_conntrack_msg_type type,
			   	      struct nf_expect *exp, 
				      void *data),
			   void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = malloc(sizeof(struct __data_container));
	if (!container)
		return -1;
	memset(container, 0, sizeof(struct __data_container));

	h->expect_cb = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb.call = __expect_callback;
	h->nfnl_cb.data = container;
	h->nfnl_cb.attr_count = CTA_EXPECT_MAX;

	nfnl_callback_register(h->nfnlssh_exp, 
			       IPCTNL_MSG_EXP_NEW,
			       &h->nfnl_cb);

	nfnl_callback_register(h->nfnlssh_exp,
			       IPCTNL_MSG_EXP_DELETE,
			       &h->nfnl_cb);

	return 0;
}

/**
 * nfexp_callback_unregister - unregister a callback
 * @h: library handler
 */
void nfexp_callback_unregister(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_NEW);
	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_DELETE);

	h->expect_cb = NULL;
	free(h->nfnl_cb.data);

	h->nfnl_cb.call = NULL;
	h->nfnl_cb.data = NULL;
	h->nfnl_cb.attr_count = 0;
}

/**
 * nfexp_set_attr - set the value of a certain expect attribute
 * @exp: pointer to a valid expect 
 * @type: attribute type
 * @value: pointer to the attribute value
 *
 * Note that certain attributes are unsettable:
 * 	- ATTR_EXP_USE
 * 	- ATTR_EXP_ID
 * 	- ATTR_EXP_*_COUNTER_*
 * The call of this function for such attributes do nothing.
 */
void nfexp_set_attr(struct nf_expect *exp,
		    const enum nf_expect_attr type, 
		    const void *value)
{
	assert(exp != NULL);
	assert(value != NULL);

	if (type >= ATTR_EXP_MAX)
		return;

	if (set_exp_attr_array[type]) {
		set_exp_attr_array[type](exp, value);
		set_bit(type, exp->set);
	}
}

/**
 * nfexp_set_attr_u8 - set the value of a certain expect attribute
 * @exp: pointer to a valid expect 
 * @type: attribute type
 * @value: unsigned 8 bits attribute value
 */
void nfexp_set_attr_u8(struct nf_expect *exp,
		       const enum nf_expect_attr type, 
		       u_int8_t value)
{
	nfexp_set_attr(exp, type, &value);
}

/**
 * nfexp_set_attr_u16 - set the value of a certain expect attribute
 * @exp: pointer to a valid expect 
 * @type: attribute type
 * @value: unsigned 16 bits attribute value
 */
void nfexp_set_attr_u16(struct nf_expect *exp,
			const enum nf_expect_attr type, 
			u_int16_t value)
{
	nfexp_set_attr(exp, type, &value);
}

/**
 * nfexp_set_attr_u32 - set the value of a certain expect attribute
 * @exp: pointer to a valid expect 
 * @type: attribute type
 * @value: unsigned 32 bits attribute value
 */
void nfexp_set_attr_u32(struct nf_expect *exp,
			const enum nf_expect_attr type, 
			u_int32_t value)
{
	nfexp_set_attr(exp, type, &value);
}

/**
 * nfexp_get_attr - get an expect attribute
 * exp: pointer to a valid expect
 * @type: attribute type
 *
 * In case of success a valid pointer to the attribute requested is returned,
 * on error NULL is returned and errno is set appropiately.
 */
const void *nfexp_get_attr(const struct nf_expect *exp,
			   const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return NULL;
	}

	if (!test_bit(type, exp->set)) {
		errno = ENODATA;
		return NULL;
	}

	return get_exp_attr_array[type](exp);
}

/**
 * nfexp_get_attr_u8 - get attribute of unsigned 8-bits long
 * @exp: pointer to a valid expectation
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfexp_attr_is_set.
 */
u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
			   const enum nf_expect_attr type)
{
	const u_int8_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfexp_get_attr_u16 - get attribute of unsigned 16-bits long
 * @exp: pointer to a valid expectation
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfexp_attr_is_set.
 */
u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
			     const enum nf_expect_attr type)
{
	const u_int16_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfexp_get_attr_u32 - get attribute of unsigned 32-bits long
 * @exp: pointer to a valid expectation
 * @type: attribute type
 *
 * Returns the value of the requested attribute, if the attribute is not 
 * set, 0 is returned. In order to check if the attribute is set or not,
 * use nfexp_attr_is_set.
 */
u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
			    const enum nf_expect_attr type)
{
	const u_int32_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

/**
 * nfexp_attr_is_set - check if a certain attribute is set
 * @exp: pointer to a valid expectation object
 * @type: attribute type
 *
 * On error, -1 is returned and errno is set appropiately, otherwise
 * the value of the attribute is returned.
 */
int nfexp_attr_is_set(const struct nf_expect *exp,
		      const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return -1;
	}
	return test_bit(type, exp->set);
}

/**
 * nfexp_attr_unset - unset a certain attribute
 * @type: attribute type
 * @exp: pointer to a valid expectation object
 * 
 * On error, -1 is returned and errno is set appropiately, otherwise
 * 0 is returned.
 */
int nfexp_attr_unset(struct nf_expect *exp,
		     const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return -1;
	}
	unset_bit(type, exp->set);

	return 0;
}

/**
 * nfexp_build_expect - build a netlink message from a conntrack object
 * @ssh: nfnetlink subsystem handler
 * @req: buffer used to build the netlink message
 * @size: size of the buffer passed
 * @type: netlink message type
 * @flags: netlink flags
 * @exp: pointer to a conntrack object
 *
 * This is a low level function for those that require to be close to
 * netlink details via libnfnetlink. If you do want to obviate the netlink
 * details then we suggest you to use nfexp_query.
 *
 * On error, -1 is returned and errno is appropiately set.
 * On success, 0 is returned.
 */
int nfexp_build_expect(struct nfnl_subsys_handle *ssh,
		       void *req,
		       size_t size,
		       u_int16_t type,
		       u_int16_t flags,
		       const struct nf_expect *exp)
{
	assert(ssh != NULL);
	assert(req != NULL);
	assert(exp != NULL);

	return __build_expect(ssh, req, size, type, flags, exp);
}

/**
 * nfexp_build_query - build a query in netlink message format for ctnetlink
 * @ssh: nfnetlink subsystem handler
 * @qt: query type
 * @data: data required to build the query
 * @req: buffer to build the netlink message
 * @size: size of the buffer passed
 *
 * This is a low level function, use it if you want to require to work
 * with netlink details via libnfnetlink, otherwise we suggest you to
 * use nfexp_query.
 *
 * The pointer to data can be a conntrack object or the protocol family
 * depending on the request.
 *
 * For query types:
 * 	NFEXP_Q_CREATE
 * 	NFEXP_Q_DESTROY
 *
 * Pass a valid pointer to an expectation object.
 *
 * For query types:
 * 	NFEXP_Q_FLUSH
 * 	NFEXP_Q_DUMP
 *
 * Pass a valid pointer to the protocol family (u_int8_t)
 *
 * On success, 0 is returned. On error, -1 is returned and errno is set
 * appropiately.
 */
int nfexp_build_query(struct nfnl_subsys_handle *ssh,
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
		nfexp_build_expect(ssh, req, size, IPCTNL_MSG_EXP_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL, data);
		break;
	case NFCT_Q_GET:
		nfexp_build_expect(ssh, req, size, IPCTNL_MSG_EXP_GET, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_DESTROY:
		nfexp_build_expect(ssh, req, size, IPCTNL_MSG_EXP_DELETE, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_FLUSH:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_EXP_DELETE, NLM_F_REQUEST|NLM_F_ACK);
		break;
	case NFCT_Q_DUMP:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_EXP_GET, NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST|NLM_F_DUMP);
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	return 1;
}

/**
 * nfexp_parse_expect - translate a netlink message to a conntrack object
 * @type: do the translation iif the message type is of a certain type
 * @nlh: pointer to the netlink message
 * @exp: pointer to the conntrack object
 *
 * This is a low level function, use it in case that you require to work
 * with netlink details via libnfnetlink. Otherwise, we suggest you to
 * use the high level API.
 *
 * The message types are:
 *
 * NFEXP_T_NEW: parse messages with new conntracks
 * NFEXP_T_UPDATE: parse messages with conntrack updates
 * NFEXP_T_DESTROY: parse messages with conntrack destroy 
 * NFEXP_T_ALL: all message types
 *
 * The message type is a flag, therefore the can be combined, ie.
 * NFEXP_T_NEW | NFEXP_T_DESTROY to parse only new and destroy messages
 *
 * On error, NFEXP_T_ERROR is returned and errno is set appropiately. If 
 * the message received is not of the requested type then 0 is returned, 
 * otherwise this function returns the message type parsed.
 */
int nfexp_parse_expect(enum nf_conntrack_msg_type type,
		       const struct nlmsghdr *nlh,
		       struct nf_expect *exp)
{
	unsigned int flags;
	int len = nlh->nlmsg_len;
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_EXPECT_MAX];

	assert(nlh != NULL);
	assert(exp != NULL);

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0) {
		errno = EINVAL;
		return NFCT_T_ERROR;
	}

	flags = __parse_expect_message_type(nlh);
	if (!(flags & type))
		return 0;

	nfnl_parse_attr(cda, CTA_EXPECT_MAX, NFA_DATA(nfhdr), len);

	__parse_expect(nlh, cda, exp);

	return flags;
}

/**
 * nfexp_query - send a query to ctnetlink
 * @h: library handler
 * @qt: query type
 * @data: data required to send the query
 *
 * On error, -1 is returned and errno is explicitely set. On success, 0
 * is returned.
 */
int nfexp_query(struct nfct_handle *h,
	        const enum nf_conntrack_query qt,
	        const void *data)
{
	size_t size = 4096;	/* enough for now */
	char buffer[4096];
	struct nfnlhdr *req = (struct nfnlhdr *) buffer;

	assert(h != NULL);
	assert(data != NULL);

	if (nfexp_build_query(h->nfnlssh_exp, qt, data, req, size) == -1)
		return -1;

	return nfnl_query(h->nfnlh, &req->nlh);
}

/**
 * nfexp_catch - catch events
 * @h: library handler
 *
 * On error, -1 is returned and errno is set appropiately. On success, 
 * a value greater or equal to 0 is returned indicating the callback
 * verdiexp: NFEXP_CB_STOP, NFEXP_CB_CONTINUE or NFEXP_CB_STOLEN
 */
int nfexp_catch(struct nfct_handle *h)
{
	assert(h != NULL);

	return nfnl_catch(h->nfnlh);
}

/**
 * nfexp_snprintf - print a conntrack object to a buffer
 * @buf: buffer used to build the printable conntrack
 * @size: size of the buffer
 * @exp: pointer to a valid expectation object
 * @message_type: print message type (NFEXP_T_UNKNOWN, NFEXP_T_NEW,...)
 * @output_type: print type (NFEXP_O_DEFAULT, NFEXP_O_XML, ...)
 * @flags: extra flags for the output type (NFEXP_OF_LAYER3)
 *
 * If you are listening to events, probably you want to display the message 
 * type as well. In that case, set the message type parameter to any of the
 * known existing types, ie. NFEXP_T_NEW, NFEXP_T_UPDATE, NFEXP_T_DESTROY.
 * If you pass NFEXP_T_UNKNOWN, the message type will not be output. 
 *
 * Currently, the output available are:
 * 	- NFEXP_O_DEFAULT: default /proc-like output
 * 	- NFEXP_O_XML: XML output
 *
 * The output flags are:
 * 	- NFEXP_O_LAYER: include layer 3 information in the output, this is
 * 			*only* required by NFEXP_O_DEFAULT.
 *
 * On error, -1 is returned and errno is set appropiately. Otherwise,
 * 0 is returned.
 */
int nfexp_snprintf(char *buf,
		  unsigned int size,
		  const struct nf_expect *exp,
		  unsigned int msg_type,
		  unsigned int out_type,
		  unsigned int flags) 
{
	assert(buf != NULL);
	assert(size > 0);
	assert(exp != NULL);

	return __snprintf_expect(buf, size, exp, msg_type, out_type, flags);
}
