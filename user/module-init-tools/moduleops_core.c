/* Load the given section: NULL on error. */
static void *PERBIT(load_section)(ElfPERBIT(Ehdr) *hdr,
			    const char *secname,
			    unsigned long *size,
			    int conv)
{
	ElfPERBIT(Shdr) *sechdrs;
	unsigned int i;
	char *secnames;

	/* Grab section headers and strings so we can tell who is who */
	sechdrs = (void *)hdr + END(hdr->e_shoff, conv);
	secnames = (void *)hdr
		+ END(sechdrs[END(hdr->e_shstrndx, conv)].sh_offset, conv);

	/* Find the section they want */
	for (i = 1; i < END(hdr->e_shnum, conv); i++) {
		if (streq(secnames+END(sechdrs[i].sh_name, conv), secname)) {
			*size = END(sechdrs[i].sh_size, conv);
			return (void *)hdr + END(sechdrs[i].sh_offset, conv);
		}
	}
	*size = 0;
	return NULL;
}

static void PERBIT(load_symbols)(struct module *module)
{
	struct PERBIT(kernel_symbol) *ksyms;
	char *ksymstrings;
	unsigned long i, size;

	/* New-style: strings are in this section. */
	ksymstrings = PERBIT(load_section)(module->data, "__ksymtab_strings",
					   &size, module->conv);
	if (ksymstrings) {
		unsigned int i = 0;
		for (;;) {
			/* Skip any zero padding. */
			while (!ksymstrings[i])
				if (++i >= size)
					return;
			add_symbol(ksymstrings+i, module);
			i += strlen(ksymstrings+i);
		}
		/* GPL symbols too */
		ksymstrings = PERBIT(load_section)(module->data,
						   "__ksymtab_strings_gpl",
						   &size, module->conv);
		for (;;) {
			/* Skip any zero padding. */
			while (!ksymstrings[i])
				if (++i >= size)
					return;
			add_symbol(ksymstrings+i, module);
			i += strlen(ksymstrings+i);
		}
		return;
	}

	/* Old-style. */
	ksyms = PERBIT(load_section)(module->data, "__ksymtab", &size,
				     module->conv);
	for (i = 0; i < size / sizeof(struct PERBIT(kernel_symbol)); i++)
		add_symbol(ksyms[i].name, module);
	ksyms = PERBIT(load_section)(module->data, "__gpl_ksymtab", &size,
				     module->conv);
	for (i = 0; i < size / sizeof(struct PERBIT(kernel_symbol)); i++)
		add_symbol(ksyms[i].name, module);
}

static char *PERBIT(get_aliases)(struct module *module, unsigned long *size)
{
	return PERBIT(load_section)(module->data, ".modalias", size,
				    module->conv);
}

static char *PERBIT(get_modinfo)(struct module *module, unsigned long *size)
{
	return PERBIT(load_section)(module->data, ".modinfo", size,
				    module->conv);
}

#ifndef STT_REGISTER
#define STT_REGISTER    13              /* Global register reserved to app. */
#endif

/* Calculate the dependencies for this module */
static void PERBIT(calculate_deps)(struct module *module, int verbose)
{
	unsigned int i;
	unsigned long size;
	char *strings;
	ElfPERBIT(Sym) *syms;
	ElfPERBIT(Ehdr) *hdr;
	int handle_register_symbols;

	strings = PERBIT(load_section)(module->data, ".strtab", &size,
				       module->conv);
	syms = PERBIT(load_section)(module->data, ".symtab", &size,
				    module->conv);

	module->num_deps = 0;
	module->deps = NULL;

	if (!strings || !syms) {
		warn("Couldn't find symtab and strtab in module %s\n",
		     module->pathname);
		return;
	}

	hdr = module->data;
	handle_register_symbols = 0;
	if (END(hdr->e_machine, module->conv) == EM_SPARC ||
	    END(hdr->e_machine, module->conv) == EM_SPARCV9)
		handle_register_symbols = 1;

	for (i = 1; i < size / sizeof(syms[0]); i++) {
		if (END(syms[i].st_shndx, module->conv) == SHN_UNDEF) {
			/* Look for symbol */
			const char *name;
			struct module *owner;
			int weak;

			name = strings + END(syms[i].st_name, module->conv);

			/* Not really undefined: sparc gcc 3.3 creates
                           U references when you have global asm
                           variables, to avoid anyone else misusing
                           them. */
			if (handle_register_symbols
			    && (ELFPERBIT(ST_TYPE)(END(syms[i].st_info,
						       module->conv))
				== STT_REGISTER))
				continue;

			weak = (ELFPERBIT(ST_BIND)(END(syms[i].st_info,
						       module->conv))
				== STB_WEAK);
			owner = find_symbol(name, module->pathname, weak);
			if (owner) {
				if (verbose)
					printf("%s needs \"%s\": %s\n",
					       module->pathname, name,
					       owner->pathname);
				add_dep(module, owner);
			}
		}
	}
}

static void *PERBIT(deref_sym)(ElfPERBIT(Ehdr) *hdr, const char *name,
			       unsigned int *secsize,
			       int conv)
{
	unsigned int i;
	unsigned long size;
	char *strings;
	ElfPERBIT(Sym) *syms;
	ElfPERBIT(Shdr) *sechdrs;

	sechdrs = (void *)hdr + END(hdr->e_shoff, conv);
	strings = PERBIT(load_section)(hdr, ".strtab", &size, conv);
	syms = PERBIT(load_section)(hdr, ".symtab", &size, conv);

	/* Don't warn again: we already have above */
	if (!strings || !syms)
		return NULL;

	for (i = 0; i < size / sizeof(syms[0]); i++) {
		if (streq(strings + END(syms[i].st_name, conv), name)) {
			/* In BSS?  Happens for empty device tables on
			 * recent GCC versions. */
			if (END(sechdrs[END(syms[i].st_shndx, conv)].sh_type,
				conv) == SHT_NOBITS)
				return NULL;
			if (secsize)
				*secsize = END(syms[i].st_size, conv);
			return (void *)hdr
				+ END(sechdrs[END(syms[i].st_shndx, conv)]
				      .sh_offset, conv)
				+ END(syms[i].st_value, conv);
		}
	}
	return NULL;
}

/* FIXME: Check size, unless we end up using aliases anyway --RR */
static void PERBIT(fetch_tables)(struct module *module)
{
	module->pci_size = PERBIT(PCI_DEVICE_SIZE);
	module->pci_table = PERBIT(deref_sym)(module->data,
					"__mod_pci_device_table",
					NULL, module->conv);

	module->usb_size = PERBIT(USB_DEVICE_SIZE);
	module->usb_table = PERBIT(deref_sym)(module->data,
					"__mod_usb_device_table",
					NULL, module->conv);

	module->ccw_size = PERBIT(CCW_DEVICE_SIZE);
	module->ccw_table = PERBIT(deref_sym)(module->data,
					"__mod_ccw_device_table",
					NULL, module->conv);

	module->ieee1394_size = PERBIT(IEEE1394_DEVICE_SIZE);
	module->ieee1394_table = PERBIT(deref_sym)(module->data,
					"__mod_ieee1394_device_table",
					NULL, module->conv);

	module->pnp_size = PERBIT(PNP_DEVICE_SIZE);
	module->pnp_table = PERBIT(deref_sym)(module->data,
					"__mod_pnp_device_table",
					NULL, module->conv);

	module->pnp_card_size = PERBIT(PNP_CARD_DEVICE_SIZE);
	module->pnp_card_table = PERBIT(deref_sym)(module->data,
					"__mod_pnp_card_device_table",
					NULL, module->conv);
	module->pnp_card_offset = PERBIT(PNP_CARD_DEVICE_OFFSET);

	module->input_size = PERBIT(INPUT_DEVICE_SIZE);
	module->input_table = PERBIT(deref_sym)(module->data,
					"__mod_input_device_table",
					&module->input_table_size,
						module->conv);

	module->serio_size = PERBIT(SERIO_DEVICE_SIZE);
	module->serio_table = PERBIT(deref_sym)(module->data,
					"__mod_serio_device_table",
					NULL, module->conv);

	module->of_size = PERBIT(OF_DEVICE_SIZE);
	module->of_table = PERBIT(deref_sym)(module->data,
					"__mod_of_device_table",
					NULL, module->conv);
}

struct module_ops PERBIT(mod_ops) = {
	.load_symbols	= PERBIT(load_symbols),
	.calculate_deps	= PERBIT(calculate_deps),
	.fetch_tables	= PERBIT(fetch_tables),
	.get_aliases	= PERBIT(get_aliases),
	.get_modinfo	= PERBIT(get_modinfo),
};
