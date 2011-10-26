ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

# Include directories for CVS version
CFLAGS += -I../driver/modules -I../utils -I../hostapd

# Uncomment following two lines and fix the paths if you have installed openssl
# in non-default location
#CFLAGS += -I/usr/local/openssl/include
#LIBS += -L/usr/local/openssl/lib

# Uncomment following two lines to use portable libdnet and libpcap instead of
# Linux-specific internal implementation for L2 packet handling
#CFLAGS += -DUSE_DNET_PCAP
#LIBS=-ldnet -lpcap

all: verify_config wpa_supplicant wpa_passphrase wpa_cli

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building wpa_supplicant request a configuration file'; \
		echo '(.config). See README for more instructions or run'; \
		echo '"make mkconfig" to create an example configuration.'; \
		exit 1; \
	fi

mkconfig:
	@if [ -e .config ]; then \
		echo '.config exists - did not replace it'; \
		exit 1; \
	fi
	echo CONFIG_DRIVER_HOSTAP=y >> .config
	echo CONFIG_DRIVER_WEXT=y >> .config
	echo CONFIG_WIRELESS_EXTENSION=y >> .config

OBJS = config.o ctrl_iface.o \
	eloop.o common.o md5.o \
	rc4.o sha1.o aes_wrap.o
OBJS_p = wpa_passphrase.o sha1.o
OBJS_c = wpa_cli.o wpa_ctrl.o

-include .config

ifdef CONFIG_EAPOL_TEST
CFLAGS += -Werror -DEAPOL_TEST
endif

ifdef CONFIG_DRIVER_HOSTAP
CFLAGS += -DCONFIG_DRIVER_HOSTAP
OBJS += driver_hostap.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_WEXT
CFLAGS += -DCONFIG_DRIVER_WEXT
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_PRISM54
CFLAGS += -DCONFIG_DRIVER_PRISM54
OBJS += driver_prism54.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_HERMES
CFLAGS += -DCONFIG_DRIVER_HERMES
CFLAGS += -I../../hcf -I../../include -I../../include/hcf
CFLAGS += -I../../include/wireless
OBJS += driver_hermes.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_MADWIFI
CFLAGS += -DCONFIG_DRIVER_MADWIFI
CFLAGS += -I../madwifi/wpa		# change to reflect local setup
OBJS += driver_madwifi.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_ATMEL
CFLAGS += -DCONFIG_DRIVER_ATMEL
OBJS += driver_atmel.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_NDISWRAPPER
CFLAGS += -DCONFIG_DRIVER_NDISWRAPPER
OBJS += driver_ndiswrapper.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_EAP_TLS
# EAP-TLS
CFLAGS += -DEAP_TLS
OBJS += eap_tls.o
TLS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_PEAP
# EAP-PEAP
CFLAGS += -DEAP_PEAP
OBJS += eap_peap.o
TLS_FUNCS=y
CONFIG_MSCHAPV2=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_TTLS
# EAP-TTLS
CFLAGS += -DEAP_TTLS
OBJS += eap_ttls.o
MS_FUNCS=y
TLS_FUNCS=y
CONFIG_EAP_MD5=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_MD5
# EAP-MD5 (also used by EAP-TTLS)
CFLAGS += -DEAP_MD5
OBJS += eap_md5.o
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_MSCHAPV2
# EAP-MSCHAPv2 (also used by EAP-PEAP)
CFLAGS += -DEAP_MSCHAPv2
OBJS += eap_mschapv2.o
MS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_GTC
# EAP-GTC (also used by EAP-PEAP)
CFLAGS += -DEAP_GTC
OBJS += eap_gtc.o
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_OTP
# EAP-OTP
CFLAGS += -DEAP_OTP
OBJS += eap_otp.o
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_SIM
# EAP-SIM
CFLAGS += -DEAP_SIM
OBJS += eap_sim.o
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_LEAP
# EAP-LEAP
CFLAGS += -DEAP_LEAP
OBJS += eap_leap.o
MS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_IEEE8021X_EAPOL
# IEEE 802.1X/EAPOL state machines (e.g., for RADIUS authentication)
CFLAGS += -DIEEE8021X_EAPOL
OBJS += eapol_sm.o eap.o
endif

ifdef CONFIG_PCSC
# PC/SC interface for smartcards (USIM, GSM SIM)
CFLAGS += -DPCSC_FUNCS
OBJS += pcsc_funcs.o
# -lpthread may not be needed depending on how pcsc-lite was configured
LIBS += -lpcsclite -lpthread
endif

ifdef TLS_FUNCS
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, and EAP_TTLS)
CFLAGS += -DEAP_TLS_FUNCS
OBJS += eap_tls_common.o
LIBS += -lssl
LIBS_p += -lcrypto
endif

ifdef MS_FUNCS
ifndef TLS_FUNCS
LIBS += -lcrypto
endif
OBJS += ms_funcs.o
endif

ifdef CONFIG_WIRELESS_EXTENSION
CFLAGS += -DCONFIG_WIRELESS_EXTENSION
OBJS += driver_wext.o
endif

OBJS_t := $(OBJS) eapol_test.o radius.o radius_client.o
OBJS += wpa_supplicant.o wpa.o l2_packet.o

wpa_supplicant: .config $(OBJS)
	$(CC) -o wpa_supplicant $(OBJS) $(LIBS)

eapol_test: .config $(OBJS_t)
	$(CC) -o eapol_test $(OBJS_t) $(LIBS)

wpa_passphrase: $(OBJS_p)
	$(CC) -o wpa_passphrase $(OBJS_p) $(LIBS_p)

wpa_cli: $(OBJS_c)
	$(CC) -o wpa_cli $(OBJS_c)

clean:
	rm -f core *~ *.o wpa_supplicant wpa_passphrase wpa_cli *.d

-include $(OBJS:%.o=%.d)
