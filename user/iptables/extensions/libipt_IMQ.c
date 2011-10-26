/* Shared library add-on to iptables to add IMQ target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_IMQ.h>

static void
help(void)
{
	printf(
"IMQ target options:\n"
"  --todev <N>		enqueue to imq<N>, defaults to 0\n");
}

static struct option opts[] = {
	{ "todev", 1, 0, '1' },
	{ .name = NULL }
};

static void
init(struct xt_entry_target *t)
{
	struct ipt_imq_info *mr = (struct ipt_imq_info*)t->data;

	mr->todev = 0;
}

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target)
{
	struct ipt_imq_info *mr = (struct ipt_imq_info*)(*target)->data;
	
	switch(c) {
	case '1':
		if (xtables_check_inverse(optarg, &invert, NULL, 0))
			xtables_error(PARAMETER_PROBLEM,
				   "Unexpected `!' after --todev");
		mr->todev=atoi(optarg);
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
	struct ipt_imq_info *mr = (struct ipt_imq_info*)target->data;

	printf("IMQ: todev %u ", mr->todev);
}

static void
save(const void *ip, const struct xt_entry_target *target)
{
	struct ipt_imq_info *mr = (struct ipt_imq_info*)target->data;

	printf("--todev %u", mr->todev);
}

static
struct xtables_target imq
= {
    .name = "IMQ",
    .version = XTABLES_VERSION,
    .family = NFPROTO_IPV4,
    .size = XT_ALIGN(sizeof(struct ipt_imq_info)),
    .userspacesize = XT_ALIGN(sizeof(struct ipt_imq_info)),
    .help = &help,
    .init = &init,
    .parse = &parse,
    .final_check = &final_check,
    .print = &print,
    .save = &save,
    .extra_opts = opts
};

void _init(void)
{
	xtables_register_target(&imq);
}
