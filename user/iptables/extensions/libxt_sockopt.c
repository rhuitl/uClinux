/*
 *	libxt_sockopt
 *	Shared library add-on to iptables for socket field matching support.
 */
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_sockopt.h>

static void sockopt_mt_help(void)
{
	printf(
"sockopt match options:\n"
"[!] --soorigdev devname\n"
"[!] --soorigsrc address[/mask]\n"
"[!] --soorigsrc address-address\n"
"[!] --soorigdst address[/mask]\n"
"[!] --soorigdst address-address\n"
);
}

static const struct option sockopt_mt_opts[] = {
	{.name = "soorigdev",         .has_arg = true, .val = '1'},
	{.name = "soorigsrc",         .has_arg = true, .val = '2'},
	{.name = "soorigdst",         .has_arg = true, .val = '3'},
	{.name = NULL},
};

static int parse_addr(struct in_addr *addr, struct in_addr *mask, char *arg)
{
	struct in_addr *ip;
	char *dash;

	dash = strrchr(arg, '-');
	if (dash != NULL) {
		*dash = '\0';
		ip = xtables_numeric_to_ipaddr(arg);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM,
				"sockopt match: Bad IP address \"%s\"\n", arg);
		*addr = *ip;

		ip = xtables_numeric_to_ipaddr(dash + 1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM,
				"sockopt match: Bad IP address \"%s\"\n",
				dash + 1);
		*mask = *ip;

		return 1;
	} else {
		struct in_addr *addrs = NULL;
		unsigned int naddrs = 0;

		xtables_ipparse_any(arg, &addrs, mask, &naddrs);
		if (naddrs > 1)
			xtables_error(PARAMETER_PROBLEM,
				"multiple IP addresses not allowed");
		if (naddrs == 1)
			memcpy(addr, addrs, sizeof(*addrs));

		return 0;
	}
}

static int sockopt_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                            const void *entry, struct xt_entry_match **match)
{
	struct xt_sockopt_mtinfo *info = (void *)(*match)->data;
	unsigned int dev;
	char *end;

	switch (c) {
	case '1':
		xtables_param_act(XTF_ONLY_ONCE, "sockopt", "--soorigdev", *flags & XT_SOCKOPT_ORIGDEV);
		if (!xtables_strtoui(optarg, &end, &dev, 0, UINT32_MAX))
			xtables_param_act(XTF_BAD_VALUE, "sockopt", "--soorigdev", optarg);
		if (*end != '\0')
			xtables_param_act(XTF_BAD_VALUE, "sockopt", "--soorigdev", optarg);
		info->origdev = dev;
		if (invert)
			info->invert |= XT_SOCKOPT_ORIGDEV;
		info->match |= XT_SOCKOPT_ORIGDEV;
		*flags |= XT_SOCKOPT_ORIGDEV;
		return true;

	case '2':
		xtables_param_act(XTF_ONLY_ONCE, "sockopt", "--soorigsrc", *flags & XT_SOCKOPT_ORIGSRC);
		if (parse_addr(&info->origsrc_addr.in, &info->origsrc_mask.in,
					argv[optind-1]))
			info->match |= XT_SOCKOPT_SRCRANGE;
		if (invert)
			info->invert |= XT_SOCKOPT_ORIGSRC;
		info->match |= XT_SOCKOPT_ORIGSRC;
		*flags |= XT_SOCKOPT_ORIGSRC;
		return true;

	case '3':
		xtables_param_act(XTF_ONLY_ONCE, "sockopt", "--soorigdst", *flags & XT_SOCKOPT_ORIGDST);
		if (parse_addr(&info->origdst_addr.in, &info->origdst_mask.in,
					argv[optind-1]))
			info->match |= XT_SOCKOPT_DSTRANGE;
		if (invert)
			info->invert |= XT_SOCKOPT_ORIGDST;
		info->match |= XT_SOCKOPT_ORIGDST;
		*flags |= XT_SOCKOPT_ORIGDST;
		return true;

	default:
		return false;
	}
}

static void sockopt_mt_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "sockopt: At least one option "
		           "is required");
}

static void
sockopt_dump_addr(const union nf_inet_addr *addr,
                    const union nf_inet_addr *mask, int range,
                    unsigned int family, bool numeric)
{
	if (family == NFPROTO_IPV4) {
		if (!numeric && addr->ip == 0) {
			printf("anywhere ");
		} else if (range) {
			printf("%s-%s ", xtables_ipaddr_to_numeric(&addr->in),
					xtables_ipaddr_to_numeric(&mask->in));
		} else if (numeric) {
			printf("%s%s ", xtables_ipaddr_to_numeric(&addr->in),
					xtables_ipmask_to_numeric(&mask->in));
		} else {
			printf("%s%s ", xtables_ipaddr_to_anyname(&addr->in),
					xtables_ipmask_to_numeric(&mask->in));
		}
	} else if (family == NFPROTO_IPV6) {
		if (!numeric && addr->ip6[0] == 0 && addr->ip6[1] == 0 &&
		    addr->ip6[2] == 0 && addr->ip6[3] == 0) {
			printf("anywhere ");
		} else if (range) {
			printf("%s-%s ", xtables_ip6addr_to_numeric(&addr->in6),
					xtables_ip6addr_to_numeric(&mask->in6));
		} else if (numeric) {
			printf("%s%s ", xtables_ip6addr_to_numeric(&addr->in6),
					xtables_ip6mask_to_numeric(&mask->in6));
		} else {
			printf("%s%s ", xtables_ip6addr_to_anyname(&addr->in6),
					xtables_ip6mask_to_numeric(&mask->in6));
		}
	}
}

static void
sockopt_dump(const struct xt_sockopt_mtinfo *info, const char *prefix,
               unsigned int family, bool numeric)
{
	if (info->match & XT_SOCKOPT_ORIGDEV) {
		if (info->invert & XT_SOCKOPT_ORIGDEV)
			printf("! ");
		printf("%ssoorigdev ", prefix);
		printf("%u ", info->origdev);
	}

	if (info->match & XT_SOCKOPT_ORIGSRC) {
		if (info->invert & XT_SOCKOPT_ORIGSRC)
			printf("! ");
		printf("%ssoorigsrc ", prefix);
		sockopt_dump_addr(
			&info->origsrc_addr,
			&info->origsrc_mask,
			info->match & XT_SOCKOPT_SRCRANGE,
			family, numeric);
	}

	if (info->match & XT_SOCKOPT_ORIGDST) {
		if (info->invert & XT_SOCKOPT_ORIGDST)
			printf("! ");
		printf("%ssoorigsrc ", prefix);
		sockopt_dump_addr(
			&info->origdst_addr,
			&info->origdst_mask,
			info->match & XT_SOCKOPT_DSTRANGE,
			family, numeric);
	}
}

static void
sockopt_mt_print(const void *ip, const struct xt_entry_match *match,
                   int numeric)
{
	sockopt_dump((const void *)match->data, "", NFPROTO_IPV4, numeric);
}

static void sockopt_mt_save(const void *ip,
                              const struct xt_entry_match *match)
{
	sockopt_dump((const void *)match->data, "--", NFPROTO_IPV4, true);
}

static struct xtables_match sockopt_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "sockopt",
	.revision      = 0,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_sockopt_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_sockopt_mtinfo)),
	.help          = sockopt_mt_help,
	.parse         = sockopt_mt_parse,
	.final_check   = sockopt_mt_check,
	.print         = sockopt_mt_print,
	.save          = sockopt_mt_save,
	.extra_opts    = sockopt_mt_opts,
};

void _init(void)
{
	xtables_register_match(&sockopt_mt_reg);
}
