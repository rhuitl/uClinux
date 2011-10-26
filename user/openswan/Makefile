
OPENSWANSRCDIR := $(ROOTDIR)/openswan
include $(OPENSWANSRCDIR)/Makefile.inc

programs:  dummy_target
	if [ -d $(OPENSWANSRCDIR) ]; then \
		ROOTDIR="$(ROOTDIR)" LDFLAGS="$(LDFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) -C $(OPENSWANSRCDIR) $@ ; \
	fi

clean:  dummy_target
	if [ -d $(OPENSWANSRCDIR) ]; then \
		ROOTDIR="$(ROOTDIR)" CFLAGS="$(CFLAGS)" LDLIBS="$(LDLIBS)" $(MAKE) -C $(OPENSWANSRCDIR) $@ ; \
	fi

romfs:
ifneq ($(CONFIG_USER_IPSEC_CONFIGURATOR)$(CONFIG_PROP_IFMOND_IPSEC),)
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(OBJDIRTOP)/programs/pluto/pluto /bin/pluto
	-$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_PLUTO $(OBJDIRTOP)/programs/pluto/_pluto_adns /bin/_pluto_adns
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PLUTO_WHACK $(OBJDIRTOP)/programs/pluto/whack /bin/whack
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RANBITS $(OBJDIRTOP)/programs/ranbits/ranbits /bin/ranbits
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_UTILS_RSASIGKEY $(OBJDIRTOP)/programs/rsasigkey/rsasigkey /bin/rsasigkey
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_EROUTE $(OBJDIRTOP)/programs/eroute/eroute /bin/eroute
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_KLIPSDEBUG $(OBJDIRTOP)/programs/klipsdebug/klipsdebug /bin/klipsdebug
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPI $(OBJDIRTOP)/programs/spi/spi /bin/spi
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_SPIGRP $(OBJDIRTOP)/programs/spigrp/spigrp /bin/spigrp
	$(ROMFSINST) -e CONFIG_USER_OPENSWAN_KLIPS_TNCFG $(OBJDIRTOP)/programs/tncfg/tncfg /bin/tncfg
	-$(ROMFSINST) -e CONFIG_USER_OPENSWAN_PROGRAMS_LWDNSQ $(OBJDIRTOP)/programs/lwdnsq/lwdnsq /bin/lwdnsq
else
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/spi/spi /bin/spi
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/barf/barf /bin/barf
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/auto/auto /bin/auto
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/look/look /bin/look
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/ranbits/ranbits /bin/ranbits
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_realsetup/_realsetup /bin/_realsetup
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_include/_include /bin/_include
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/ipsec/ipsec /bin/ipsec
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/pluto/pluto /bin/pluto
	-$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/pluto/_pluto_adns /bin/_pluto_adns
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/pluto/whack /bin/whack
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/setup/setup /bin/setup
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/tncfg/tncfg /bin/tncfg
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_plutoload/_plutoload /bin/_plutoload
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/secrets/secrets /bin/secrets
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/klipsdebug/klipsdebug /bin/klipsdebug
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/newhostkey/newhostkey /bin/newhostkey
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/showhostkey/showhostkey /bin/showhostkey
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_keycensor/_keycensor /bin/_keysensor
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_plutorun/_plutorun /bin/_plutorun
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/eroute/eroute /bin/eroute
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_updown/_updown /bin/_updown
	-$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/lwdnsq/lwdnsq /bin/lwdnsq
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/rsasigkey/rsasigkey /bin/rsasigkey
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/pf_key/pf_key /bin/pf_key
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/spigrp/spigrp /bin/spigrp
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/showpolicy/showpolicy /bin/showpolicy
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/verify/verify /bin/verify
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_secretcensor/_secretcensor /bin/_secretcensor
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_copyright/_copyright /bin/_copyright
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/ikeping/ikeping /bin/ikeping
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/showdefaults/showdefaults /bin/showdefaults
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_startklips/_startklips /bin/_startklips
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_startnetkey/_startnetkey /bin/_startnetkey
	$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_updown.klips/_updown.klips /bin/_updown.klips
	-$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_updown.mast/_updown.mast /bin/_updown.mast
	-$(ROMFSINST) -p 555 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/_updown.netkey/_updown.netkey /bin/_updown.netkey
	$(ROMFSINST) -p 755 -e CONFIG_USER_OPENSWAN $(OBJDIRTOP)/programs/addconn/addconn /bin/addconn
endif

dummy_target:
