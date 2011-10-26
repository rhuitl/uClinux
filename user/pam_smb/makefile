.EXPORT_ALL_VARIABLES:

all: .build
	$(MAKE) -f Makefile all

.build:
	chmod +x configure
	./configure $(CONFIGURE_OPTS) $(CONFOPTS)
	touch .build

.IGNORE: clean
clean:
	@make -f Makefile extraclean
	@rm -f .build

romfs:
	$(ROMFSINST) /lib/security/pam_smb_auth.so

%: .build
	$(MAKE) -f Makefile $@
