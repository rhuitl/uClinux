/* Shared library add-on to iptables to add CONNLOG target support. */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_CONNLOG.h>

static void
help(void)
{
	printf(
"CONNLOG target options:\n"
"  --confirm       Log confirm events\n"
"  --destroy       Log destroy events\n");
}

static struct option opts[] = {
	{ "confirm", 0, 0, '1' },
	{ "destroy", 0, 0, '2' },
	{ .name = NULL }
};

static void
init(struct xt_entry_target *t)
{
}

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	struct ipt_connlog_target_info *loginfo
		= (struct ipt_connlog_target_info *)(*target)->data;

	switch (c) {
	case '1':
		loginfo->events |= IPT_CONNLOG_CONFIRM;
		break;
	case '2':
		loginfo->events |= IPT_CONNLOG_DESTROY;
		break;
	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
}

static void
print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
	const struct ipt_connlog_target_info *loginfo =
		(const struct ipt_connlog_target_info *)target->data;

	printf("CONNLOG");
	if (loginfo->events & IPT_CONNLOG_CONFIRM)
		printf(" confirm");
	if (loginfo->events & IPT_CONNLOG_DESTROY)
		printf(" destroy");
}

static void
save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_connlog_target_info *loginfo =
		(const struct ipt_connlog_target_info *)target->data;

	if (loginfo->events & IPT_CONNLOG_CONFIRM)
		printf("--confirm ");
	if (loginfo->events & IPT_CONNLOG_DESTROY)
		printf("--destroy ");
}

static struct xtables_target connlog_target = {
    .name          = "CONNLOG",
    .version       = XTABLES_VERSION,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct ipt_connlog_target_info)),
    .userspacesize = XT_ALIGN(sizeof(struct ipt_connlog_target_info)),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .print         = &print,
    .save          = &save,
    .extra_opts    = opts
};

void _init(void)
{
	xtables_register_target(&connlog_target);
}
