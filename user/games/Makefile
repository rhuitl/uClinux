#
#	Makefile -- Build instructions for user games level apps
#

.EXPORT_ALL_VARIABLES:

dir_y = 
dir_n =
dir_ = 

dir_$(CONFIG_USER_GAMES_ADVENT4)        += advent4
dir_$(CONFIG_USER_GAMES_DUNGEON)        += dungeon
dir_$(CONFIG_USER_GAMES_RUBIK)          += rubik
dir_$(CONFIG_USER_GAMES_TAMA)		+= tama
#dir_$(CONFIG_USER_GAMES_XMAME)		    += xmame

all:
	for i in $(dir_y) dummy ; do \
		[ $$i = dummy ] || make -C $$i || exit $? ; \
	done

romfs:
	for i in $(dir_y) dummy ; do \
		[ $$i = dummy ] || make -C $$i romfs || exit $? ; \
	done

clean:
	-for i in $(dir_y) $(dir_n) $(dir_) ; do \
		[ ! -d $$i ] || make -C $$i clean; \
	done

