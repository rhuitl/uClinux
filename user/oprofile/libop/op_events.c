/**
 * @file op_events.c
 * Details of PMC profiling events
 *
 * You can have silliness here.
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#include "op_events.h"
#include "op_libiberty.h"
#include "op_fileio.h"
#include "op_string.h"
#include "op_cpufreq.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static LIST_HEAD(events_list);
static LIST_HEAD(um_list);

static char const * filename;
static unsigned int line_nr;

static void parse_error(char const * context)
{
	fprintf(stderr, "oprofile: parse error in %s, line %u\n",
		filename, line_nr);
	fprintf(stderr, "%s\n", context);
	exit(EXIT_FAILURE);
}


static int parse_int(char const * str)
{
	int value;
	if (sscanf(str, "%d", &value) != 1)
		parse_error("expected decimal value");

	return value;
}


static int parse_hex(char const * str)
{
	int value;
	if (sscanf(str, "%x", &value) != 1)
		parse_error("expected hexadecimal value");

	return value;
}


static u64 parse_long_hex(char const * str)
{
	u64 value;
	if (sscanf(str, "%Lx", &value) != 1)
		parse_error("expected long hexadecimal value");

	fflush(stderr);
	return value;
}


/* name:MESI type:bitmask default:0x0f */
static void parse_um(struct op_unit_mask * um, char const * line)
{
	int seen_name = 0;
	int seen_type = 0;
       	int seen_default = 0;
	char const * valueend = line + 1;
       	char const * tagend = line + 1;
	char const * start = line;

	while (*valueend) {
		valueend = skip_nonws(valueend);

		while (*tagend != ':' && *tagend)
			++tagend;

		if (valueend == tagend)
			break;

		if (!*tagend)
			parse_error("parse_um() expected :value");

		++tagend;

		if (strisprefix(start, "name")) {
			if (seen_name)
				parse_error("duplicate name: tag");
			seen_name = 1;
			um->name = op_xstrndup(tagend, valueend - tagend);
		} else if (strisprefix(start, "type")) {
			if (seen_type)
				parse_error("duplicate type: tag");
			seen_type = 1;
			if (strisprefix(tagend, "mandatory")) {
				um->unit_type_mask = utm_mandatory;
			} else if (strisprefix(tagend, "bitmask")) {
				um->unit_type_mask = utm_bitmask;
			} else if (strisprefix(tagend, "exclusive")) {
				um->unit_type_mask = utm_exclusive;
			} else {
				parse_error("invalid unit mask type");
			}
		} else if (strisprefix(start, "default")) {
			if (seen_default)
				parse_error("duplicate default: tag");
			seen_default = 1;
			um->default_mask = parse_hex(tagend);
		} else {
			parse_error("invalid unit mask tag");
		}

		valueend = skip_ws(valueend);
		tagend = valueend;
		start = valueend;
	}
}


/* \t0x08 (M)odified cache state */
static void parse_um_entry(struct op_described_um * entry, char const * line)
{
	char const * c = line;

	c = skip_ws(c);
	entry->value = parse_hex(c);
	c = skip_nonws(c);

	if (!*c)
		parse_error("invalid unit mask entry");

	c = skip_ws(c);

	if (!*c)
		parse_error("invalid unit mask entry");

	entry->desc = xstrdup(c);
}


static struct op_unit_mask * new_unit_mask(void)
{
	struct op_unit_mask * um = xmalloc(sizeof(struct op_unit_mask));
	memset(um, '\0', sizeof(struct op_unit_mask));
	list_add_tail(&um->um_next, &um_list);

	return um;
}


/*
 * name:zero type:mandatory default:0x0
 * \t0x0 No unit mask
 */
static void read_unit_masks(char const * file)
{
	struct op_unit_mask * um = NULL;
	char * line;
	FILE * fp = fopen(file, "r");

	if (!fp) {
		fprintf(stderr,
			"oprofile: could not open unit mask description file %s\n", file);
		exit(EXIT_FAILURE);
	}

	filename = file;
	line_nr = 1;

	line = op_get_line(fp);

	while (line) {
		if (empty_line(line) || comment_line(line))
			goto next;

		if (line[0] != '\t') {
			um = new_unit_mask();
			parse_um(um, line);
		} else {
			if (!um)
				parse_error("no unit mask name line");
			if (um->num >= MAX_UNIT_MASK)
				parse_error("oprofile: maximum unit mask entries exceeded");

			parse_um_entry(&um->um[um->num], line);
			++(um->num);
		}

next:
		free(line);
		line = op_get_line(fp);
		++line_nr;
	}

	fclose(fp);
}


static u32 parse_counter_mask(char const * str)
{
	u32 mask = 0;
	char const * numstart = str;

	while (*numstart) {
		mask |= 1 << parse_int(numstart);

		while (*numstart && *numstart != ',')
			++numstart;
		/* skip , unless we reach eos */
		if (*numstart)
			++numstart;

		numstart = skip_ws(numstart);
	}

	return mask;
}


static struct op_unit_mask * find_um(char const * value)
{
	struct list_head * pos;

	list_for_each(pos, &um_list) {
		struct op_unit_mask * um = list_entry(pos, struct op_unit_mask, um_next);
		if (strcmp(value, um->name) == 0)
			return um;
	}

	fprintf(stderr, "oprofile: could not find unit mask %s\n", value);
	exit(EXIT_FAILURE);
}


/* parse either a "tag:value" or a ": trailing description string" */
static int next_token(char const ** cp, char ** name, char ** value)
{
	size_t tag_len;
	size_t val_len;
	char const * c = *cp;
	char const * end;
	char const * colon;

	c = skip_ws(c);
	end = colon = c;
	end = skip_nonws(end);

	colon = strchr(colon, ':');

	if (!colon) {
		if (*c)
			parse_error("next_token(): garbage at end of line");
		return 0;
	}

	if (colon >= end)
		parse_error("next_token() expected ':'");

	tag_len = colon - c;
	val_len = end - (colon + 1);

	if (!tag_len) {
		/* : trailing description */
		end = skip_ws(end);
		*name = xstrdup("desc");
		*value = xstrdup(end);
		end += strlen(end);
	} else {
		/* tag:value */
		*name = op_xstrndup(c, tag_len);
		*value = op_xstrndup(colon + 1, val_len);
		end = skip_ws(end);
	}

	*cp = end;
	return 1;
}


static struct op_event * new_event(void)
{
	struct op_event * event = xmalloc(sizeof(struct op_event));
	memset(event, '\0', sizeof(struct op_event));
	list_add_tail(&event->event_next, &events_list);

	return event;
}


/* event:0x00 counters:0 um:zero minimum:4096 name:ISSUES : Total issues */
static void read_events(char const * file)
{
	struct op_event * event = NULL;
	char * line;
	char * name;
	char * value;
	char const * c;
	int seen_event, seen_counters, seen_um, seen_minimum, seen_name;
	FILE * fp = fopen(file, "r");

	if (!fp) {
		fprintf(stderr, "oprofile: could not open event description file %s\n", file);
		exit(EXIT_FAILURE);
	}

	filename = file;
	line_nr = 1;

	line = op_get_line(fp);

	while (line) {
		if (empty_line(line) || comment_line(line))
			goto next;

		seen_name = 0;
		seen_event = 0;
		seen_counters = 0;
		seen_um = 0;
		seen_minimum = 0;
		event = new_event();

		c = line;
		while (next_token(&c, &name, &value)) {
			if (strcmp(name, "name") == 0) {
				if (seen_name)
					parse_error("duplicate name: tag");
				seen_name = 1;
				event->name = value;
			} else if (strcmp(name, "event") == 0) {
				if (seen_event)
					parse_error("duplicate event: tag");
				seen_event = 1;
				event->val = parse_hex(value);
				free(value);
			} else if (strcmp(name, "counters") == 0) {
				if (seen_counters)
					parse_error("duplicate counters: tag");
				seen_counters = 1;
				event->counter_mask = parse_counter_mask(value);
				free(value);
			} else if (strcmp(name, "um") == 0) {
				if (seen_um)
					parse_error("duplicate um: tag");
				seen_um = 1;
				event->unit = find_um(value);
				event->unit->used = 1;
				free(value);
			} else if (strcmp(name, "minimum") == 0) {
				if (seen_minimum)
					parse_error("duplicate minimum: tag");
				seen_minimum = 1;
				event->min_count = parse_int(value);
				free(value);
			} else if (strcmp(name, "desc") == 0) {
				event->desc = value;
			} else {
				parse_error("unknown tag");
			}

			free(name);
		}
next:
		free(line);
		line = op_get_line(fp);
		++line_nr;
	}

	fclose(fp);
}


/* usefull for make check */
static void check_unit_mask(struct op_unit_mask const * um,
	char const * cpu_name)
{
	u32 i;

	if (!um->used) {
		fprintf(stderr, "um %s is not used\n", um->name);
		exit(EXIT_FAILURE);
	}

	if (um->unit_type_mask == utm_mandatory && um->num != 1) {
		fprintf(stderr, "mandatory um %s doesn't contain exactly one "
			"entry (%s)\n", um->name, cpu_name);
		exit(EXIT_FAILURE);
	} else if (um->unit_type_mask == utm_bitmask) {
		u32 default_mask = um->default_mask;
		for (i = 0; i < um->num; ++i)
			default_mask &= ~um->um[i].value;

		if (default_mask) {
			fprintf(stderr, "um %s default mask is not valid "
				"(%s)\n", um->name, cpu_name);
			exit(EXIT_FAILURE);
		}
	} else {
		for (i = 0; i < um->num; ++i) {
			if (um->default_mask == um->um[i].value)
				break;
		}

		if (i == um->num) {
			fprintf(stderr, "exclusive um %s default value is not "
				"valid (%s)\n", um->name, cpu_name);
			exit(EXIT_FAILURE);
		}
	}
}


static void load_events(op_cpu cpu_type)
{
	char const * cpu_name = op_get_cpu_name(cpu_type);
	char * event_dir;
	char * event_file;
	char * um_file;
	char * dir;
	struct list_head * pos;

	if (!list_empty(&events_list))
		return;

	dir = getenv("OPROFILE_EVENTS_DIR");
	if (dir == NULL)
		dir = OP_DATADIR;

	event_dir = xmalloc(strlen(dir) + strlen("/") + strlen(cpu_name) +
                            strlen("/") + 1);
	strcpy(event_dir, dir);
	strcat(event_dir, "/"); 

	strcat(event_dir, cpu_name);
	strcat(event_dir, "/");

	event_file = xmalloc(strlen(event_dir) + strlen("events") + 1);
	strcpy(event_file, event_dir);
	strcat(event_file, "events");

	um_file = xmalloc(strlen(event_dir) + strlen("unit_masks") + 1);
	strcpy(um_file, event_dir);
	strcat(um_file, "unit_masks");

	read_unit_masks(um_file);
	read_events(event_file);

	/* sanity check: all unit mask must be used */
	list_for_each(pos, &um_list) {
		struct op_unit_mask * um = list_entry(pos, struct op_unit_mask, um_next);

		check_unit_mask(um, cpu_name);
	}
	
	free(um_file);
	free(event_file);
	free(event_dir);
}


struct list_head * op_events(op_cpu cpu_type)
{
	load_events(cpu_type);
	return &events_list;
}


static void delete_unit_mask(struct op_unit_mask * unit)
{
	u32 cur;
	for (cur = 0 ; cur < unit->num ; ++cur) {
		if (unit->um[cur].desc)
			free(unit->um[cur].desc);
	}

	if (unit->name)
		free(unit->name);

	list_del(&unit->um_next);
	free(unit);
}


static void delete_event(struct op_event * event)
{
	if (event->name)
		free(event->name);
	if (event->desc)
		free(event->desc);

	list_del(&event->event_next);
	free(event);
}


void op_free_events(void)
{
	struct list_head * pos, * pos2;
	list_for_each_safe(pos, pos2, &events_list) {
		struct op_event * event = list_entry(pos, struct op_event, event_next);
		delete_event(event);
	}

	list_for_each_safe(pos, pos2, &um_list) {
		struct op_unit_mask * unit = list_entry(pos, struct op_unit_mask, um_next);
		delete_unit_mask(unit);
	}
}


static struct op_event * find_event(u32 nr)
{
	struct list_head * pos;

	list_for_each(pos, &events_list) {
		struct op_event * event = list_entry(pos, struct op_event, event_next);
		if (event->val == nr)
			return event;
	}

	return NULL;
}


static FILE * open_event_mapping_file(char const * cpu_name) 
{
	char * ev_map_file;
	char * dir;
	dir = getenv("OPROFILE_EVENTS_DIR");
	if (dir == NULL)
		dir = OP_DATADIR;

	ev_map_file = xmalloc(strlen(dir) + strlen("/") + strlen(cpu_name) +
	                    strlen("/") + + strlen("event_mappings") + 1);
	strcpy(ev_map_file, dir);
	strcat(ev_map_file, "/");

	strcat(ev_map_file, cpu_name);
	strcat(ev_map_file, "/");
	strcat(ev_map_file, "event_mappings");
	filename = ev_map_file;
	return (fopen(ev_map_file, "r"));
}


/**
 *  This function is PPC64-specific.
 */
static char const * get_mapping(u32 nr, FILE * fp) 
{
	char * line;
	char * name;
	char * value;
	char const * c;
	char * map = NULL;
	int seen_event = 0, seen_mmcr0 = 0, seen_mmcr1 = 0, seen_mmcra = 0;
	u32 mmcr0 = 0;
	u64 mmcr1 = 0;
	u32 mmcra = 0;
	int event_found = 0;

	line_nr = 1;
	line = op_get_line(fp);
	while (line && !event_found) {
		if (empty_line(line) || comment_line(line))
			goto next;

		seen_event = 0;
		seen_mmcr0 = 0;
		seen_mmcr1 = 0;
		seen_mmcra = 0;
		mmcr0 = 0;
		mmcr1 = 0;
		mmcra = 0;

		c = line;
		while (next_token(&c, &name, &value)) {
			if (strcmp(name, "event") == 0) {
				u32 evt;
				if (seen_event)
					parse_error("duplicate event tag");
				seen_event = 1;
				evt = parse_hex(value);
				if (evt == nr)
					event_found = 1;
				free(value);
			} else if (strcmp(name, "mmcr0") == 0) {
				if (seen_mmcr0)
					parse_error("duplicate mmcr0 tag");
				seen_mmcr0 = 1;
				mmcr0 = parse_hex(value);
				free(value);
			} else if (strcmp(name, "mmcr1") == 0) {
				if (seen_mmcr1)
					parse_error("duplicate mmcr1: tag");
				seen_mmcr1 = 1;
				mmcr1 = parse_long_hex(value);
				free(value);
			} else if (strcmp(name, "mmcra") == 0) {
				if (seen_mmcra)
					parse_error("duplicate mmcra: tag");
				seen_mmcra = 1;
				mmcra = parse_hex(value);
				free(value);
			} else {
				parse_error("unknown tag");
			}

			free(name);
		}
next:
		free(line);
		line = op_get_line(fp);
		++line_nr;
	}
	if (event_found) {
		if (!seen_mmcr0 || !seen_mmcr1 || !seen_mmcra) {
			fprintf(stderr, "Error: Missing information in line %d of event mapping file %s\n", line_nr, filename);
			exit(EXIT_FAILURE);
		}
		map = xmalloc(70);
		snprintf(map, 70, "mmcr0:%u mmcr1:%Lu mmcra:%u",
		         mmcr0, mmcr1, mmcra);
	}

	return map;
}


char const * find_mapping_for_event(u32 nr, op_cpu cpu_type)
{
	char const * cpu_name = op_get_cpu_name(cpu_type);
	FILE * fp = open_event_mapping_file(cpu_name);
	char const * map = NULL;
	switch (cpu_type) {
		case CPU_PPC64_970:
		case CPU_PPC64_POWER4:
		case CPU_PPC64_POWER5:
	        case CPU_PPC64_POWER5p:
			if (!fp) {
				fprintf(stderr, "oprofile: could not open event mapping file %s\n", filename);
				exit(EXIT_FAILURE);
			} else {
				map = get_mapping(nr, fp);
			}
			break;			
		default:
			break;
	}

	if (fp)
		fclose(fp);

	return map;
}


struct op_event * find_event_by_name(char const * name)
{
	struct list_head * pos;

	list_for_each(pos, &events_list) {
		struct op_event * event = list_entry(pos, struct op_event, event_next);
		if (strcmp(event->name, name) == 0)
			return event;
	}

	return NULL;
}


struct op_event * op_find_event(op_cpu cpu_type, u32 nr)
{
	struct op_event * event;

	load_events(cpu_type);

	event = find_event(nr);

	return event;
}


int op_check_events(int ctr, u32 nr, u32 um, op_cpu cpu_type)
{
	int ret = OP_OK_EVENT;
	struct op_event * event;
	size_t i;
	u32 ctr_mask = 1 << ctr;

	load_events(cpu_type);

	event = find_event(nr);

	if (!event) {
		ret |= OP_INVALID_EVENT;
		return ret;
	}

	if ((event->counter_mask & ctr_mask) == 0)
		ret |= OP_INVALID_COUNTER;

	if (event->unit->unit_type_mask == utm_bitmask) {
		for (i = 0; i < event->unit->num; ++i)
			um &= ~(event->unit->um[i].value);			
		
		if (um)
			ret |= OP_INVALID_UM;

	} else {
		for (i = 0; i < event->unit->num; ++i) {
			if (event->unit->um[i].value == um)
				break;
		}

		if (i == event->unit->num)
			ret |= OP_INVALID_UM;
	}

	return ret;
}


void op_default_event(op_cpu cpu_type, struct op_default_event_descr * descr)
{
	descr->name = "";
	descr->um = 0x0;
	/* A fixed value of CPU cycles; this should ensure good
	 * granulity even on faster CPUs, though it will generate more
	 * interrupts.
	 */
	descr->count = 100000;

	switch (cpu_type) {
		case CPU_PPRO:
		case CPU_PII:
		case CPU_PIII:
		case CPU_P6_MOBILE:
		case CPU_CORE:
		case CPU_CORE_2:
		case CPU_ATHLON:
		case CPU_HAMMER:
			descr->name = "CPU_CLK_UNHALTED";
			break;

		case CPU_RTC:
			descr->name = "RTC_INTERRUPTS";
			descr->count = 1024;
			break;

		case CPU_P4:
		case CPU_P4_HT2:
			descr->name = "GLOBAL_POWER_EVENTS";
			descr->um = 0x1;
			break;

		case CPU_IA64:
		case CPU_IA64_1:
		case CPU_IA64_2:
			descr->count = 1000000;
			descr->name = "CPU_CYCLES";
			break;

		case CPU_AXP_EV4:
		case CPU_AXP_EV5:
		case CPU_AXP_PCA56:
		case CPU_AXP_EV6:
		case CPU_AXP_EV67:
			descr->name = "CYCLES";
			break;

		// we could possibly use the CCNT
		case CPU_ARM_XSCALE1:
		case CPU_ARM_XSCALE2:
			descr->name = "CPU_CYCLES";
			break;

		case CPU_PPC64_970:
 		case CPU_PPC_7450:
		case CPU_PPC64_POWER4:
		case CPU_PPC64_POWER5:
		case CPU_PPC64_POWER5p:
			descr->name = "CYCLES";
			break;

		case CPU_MIPS_20K:
			descr->name = "CYCLES";
			break;

		case CPU_MIPS_24K:
			descr->name = "INSTRUCTIONS";
			break;

		case CPU_MIPS_34K:
			descr->name = "INSTRUCTIONS";
			break;

		case CPU_MIPS_5K:
		case CPU_MIPS_25K:
			descr->name = "CYCLES";
			break;

		case CPU_MIPS_R10000:
		case CPU_MIPS_R12000:
			descr->name = "INSTRUCTIONS_GRADUATED";
			break;

		case CPU_MIPS_RM7000:
		case CPU_MIPS_RM9000:
			descr->name = "INSTRUCTIONS_ISSUED";
			break;

		case CPU_MIPS_SB1:
			descr->name = "INSN_SURVIVED_STAGE7";
			break;

		case CPU_MIPS_VR5432:
		case CPU_MIPS_VR5500:
			descr->name = "INSTRUCTIONS_EXECUTED";
			break;

		case CPU_PPC_E500:
		case CPU_PPC_E500_2:
			descr->name = "CPU_CLK";
			break;
             
		// don't use default, if someone add a cpu he wants a compiler
		// warning if he forgets to handle it here.
		case CPU_TIMER_INT:
		case CPU_NO_GOOD:
		case MAX_CPU_TYPE:
			break;
	}
}
