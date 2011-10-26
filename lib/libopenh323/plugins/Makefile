SUBDIRS = audio/GSM0610 \
          audio/Speex \
          audio/iLBC \
	  audio/LPC_10 \
	  audio/G726 \
	  audio/IMA_ADPCM \
	  audio/gsm-amr

all debug opt both \
optshared debugshared bothshared \
optnoshared debugnoshared bothnoshared:
	set -e; $(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir); )

clean optclean debugclean:
	set -e; $(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir) clean; )

install:
	set -e; $(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir) $@; )

optdepend debugdepend bothdepend release tagbuild:
