
CFLAGS := $(subst -Werror,,$(CFLAGS))

.EXPORT_ALL_VARIABLES:

all clean romfs: dummy_target
	$(MAKE) -C libcrypto/libdes $@
	$(MAKE) -C lib $@
	$(MAKE) -C pluto $@
	$(MAKE) -C klips $@
	$(MAKE) -C utils $@

dummy_target:

