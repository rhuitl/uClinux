/**
 * @file op_cpu_type.c
 * CPU type determination
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "op_cpu_type.h"

struct cpu_descr {
	char const * pretty;
	char const * name;
	op_cpu cpu;
	unsigned int nr_counters;
};

static struct cpu_descr const cpu_descrs[MAX_CPU_TYPE] = {
	{ "Pentium Pro", "i386/ppro", CPU_PPRO, 2 },
	{ "PII", "i386/pii", CPU_PII, 2 },
	{ "PIII", "i386/piii", CPU_PIII, 2 },
	{ "Athlon", "i386/athlon", CPU_ATHLON, 4 },
	{ "CPU with timer interrupt", "timer", CPU_TIMER_INT, 1 },
	{ "CPU with RTC device", "rtc", CPU_RTC, 1 },
	{ "P4 / Xeon", "i386/p4", CPU_P4, 8 },
	{ "IA64", "ia64/ia64", CPU_IA64, 4 },
	{ "Itanium", "ia64/itanium", CPU_IA64_1, 4 },
	{ "Itanium 2", "ia64/itanium2", CPU_IA64_2, 4 },
	{ "AMD64 processors", "x86-64/hammer", CPU_HAMMER, 4 },
	{ "P4 / Xeon with 2 hyper-threads", "i386/p4-ht", CPU_P4_HT2, 4 },
	{ "Alpha EV4", "alpha/ev4", CPU_AXP_EV4, 2 },
	{ "Alpha EV5", "alpha/ev5", CPU_AXP_EV5, 3 },
	{ "Alpha PCA56", "alpha/pca56", CPU_AXP_PCA56, 3 },
	{ "Alpha EV6", "alpha/ev6", CPU_AXP_EV6, 2 },
	{ "Alpha EV67", "alpha/ev67", CPU_AXP_EV67, 20 },
	{ "Pentium M (P6 core)", "i386/p6_mobile", CPU_P6_MOBILE, 2 },
	{ "ARM/XScale PMU1", "arm/xscale1", CPU_ARM_XSCALE1, 3 },
	{ "ARM/XScale PMU2", "arm/xscale2", CPU_ARM_XSCALE2, 5 },
	{ "ppc64 POWER4", "ppc64/power4", CPU_PPC64_POWER4, 8 },
	{ "ppc64 POWER5", "ppc64/power5", CPU_PPC64_POWER5, 6 },
	{ "ppc64 POWER5+", "ppc64/power5+", CPU_PPC64_POWER5p, 6 },
	{ "ppc64 970", "ppc64/970", CPU_PPC64_970, 8 },
	{ "MIPS 20K", "mips/20K", CPU_MIPS_20K, 1},
	{ "MIPS 24K", "mips/24K", CPU_MIPS_24K, 2},
	{ "MIPS 25K", "mips/25K", CPU_MIPS_25K, 2},
	{ "MIPS 34K", "mips/34K", CPU_MIPS_34K, 4},
	{ "MIPS 5K", "mips/5K", CPU_MIPS_5K, 2},
	{ "MIPS R10000", "mips/r10000", CPU_MIPS_R10000, 2 },
	{ "MIPS R12000", "mips/r12000", CPU_MIPS_R12000, 4 },
	{ "QED RM7000", "mips/rm7000", CPU_MIPS_RM7000, 1 },
	{ "PMC-Sierra RM9000", "mips/rm9000", CPU_MIPS_RM9000, 2 },
	{ "Sibyte SB1", "mips/sb1", CPU_MIPS_SB1, 4 },
	{ "NEC VR5432", "mips/vr5432", CPU_MIPS_VR5432, 2 },
	{ "NEC VR5500", "mips/vr5500", CPU_MIPS_VR5500, 2 },
	{ "e500", "ppc/e500", CPU_PPC_E500, 4 },
	{ "e500v2", "ppc/e500v2", CPU_PPC_E500_2, 4 },
	{ "Core Solo / Duo", "i386/core", CPU_CORE, 2 },
	{ "PowerPC G4", "ppc/7450",  CPU_PPC_7450, 6 },
 	{ "Core 2", "i386/core_2", CPU_CORE_2, 2 },
};
 
static size_t const nr_cpu_descrs = sizeof(cpu_descrs) / sizeof(struct cpu_descr);

op_cpu op_get_cpu_type(void)
{
	int cpu_type = CPU_NO_GOOD;
	char str[100];
	FILE * fp;

	fp = fopen("/proc/sys/dev/oprofile/cpu_type", "r");
	if (!fp) {
		/* Try 2.6's oprofilefs one instead. */
		fp = fopen("/dev/oprofile/cpu_type", "r");
		if (!fp) {
			fprintf(stderr, "Unable to open cpu_type file for reading\n");
			fprintf(stderr, "Make sure you have done opcontrol --init\n");
			return cpu_type;
		}
	}

	if (!fgets(str, 99, fp)) {
		fprintf(stderr, "Could not read cpu type.\n");
		return CPU_NO_GOOD;
	}

	cpu_type = op_get_cpu_number(str);

	fclose(fp);

	return cpu_type;
}


op_cpu op_get_cpu_number(char const * cpu_string)
{
	int cpu_type = CPU_NO_GOOD;
	size_t i;
	
	for (i = 0; i < nr_cpu_descrs; ++i) {
		if (!strcmp(cpu_descrs[i].name, cpu_string)) {
			cpu_type = cpu_descrs[i].cpu;
			break;
		}
	}

	/* Attempt to convert into a number */
	if (cpu_type == CPU_NO_GOOD)
		sscanf(cpu_string, "%d\n", &cpu_type);
	
	if (cpu_type <= CPU_NO_GOOD || cpu_type >= MAX_CPU_TYPE)
		cpu_type = CPU_NO_GOOD;

	return cpu_type;
}


char const * op_get_cpu_type_str(op_cpu cpu_type)
{
	if (cpu_type <= CPU_NO_GOOD || cpu_type >= MAX_CPU_TYPE)
		return "invalid cpu type";

	return cpu_descrs[cpu_type].pretty;
}


char const * op_get_cpu_name(op_cpu cpu_type)
{
	if (cpu_type <= CPU_NO_GOOD || cpu_type >= MAX_CPU_TYPE)
		return "invalid cpu type";

	return cpu_descrs[cpu_type].name;
}


int op_get_nr_counters(op_cpu cpu_type)
{
	if (cpu_type <= CPU_NO_GOOD || cpu_type >= MAX_CPU_TYPE)
		return 0;

	return cpu_descrs[cpu_type].nr_counters;
}
