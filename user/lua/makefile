ifndef ROOTDIR
ROOTDIR=$(shell pwd)/../..
endif

ncurses-5.7_URL       = ftp://ftp.gnu.org/gnu/ncurses/ncurses-5.7.tar.gz
ncurses-5.7_CONFOPTS  = --without-cxx --without-cxx-binding

readline-6.1_URL      = ftp://ftp.cwru.edu/pub/bash/readline-6.1.tar.gz

lua-5.1.4_URL         = http://www.lua.org/ftp/lua-5.1.4.tar.gz
lua-5.1.4_MAKEVARS    = CC="$(CC) $(CFLAGS)" INSTALL_TOP='$(ROMFSDIR)/usr' linux
lua-5.1.4_CONFOPTS    = --prefix=/usr

luarocks-2.0.2_URL       = http://luarocks.org/releases/luarocks-2.0.2.tar.gz
luarocks-2.0.2_NODEFCONF = 1
luarocks-2.0.2_CONFOPTS  = \
							--prefix=/usr \
							--sysconfdir=/etc/config \
							--with-lua-include=$(ROMFSDIR)/usr/include \
							--with-lua-lib=$(ROMFSDIR)/usr/lib \
							--rocks-tree=$(ROMFSDIR)/usr \
							--force-config
luarocks-2.0.2_MAKEVARS = CC="$(CC) $(CFLAGS)"
luarocks-2.0.2_ROMFS    = luarocks_romfs

sqlite-amalgamation-3.6.23.1_URL = http://sqlite.org/sqlite-amalgamation-3.6.23.1.tar.gz
sqlite-amalgamation-3.6.23.1_BUILDDIR = sqlite-3.6.23.1
sqlite-amalgamation-3.6.23.1_CONFOPTS = --disable-threadsafe

AUTOMAKE_y =
AUTOMAKE_$(CONFIG_USER_LUA) += ncurses-5.7
AUTOMAKE_$(CONFIG_USER_LUA) += readline-6.1
AUTOMAKE_$(CONFIG_USER_LUA_LUASQL_SQLITE3) += sqlite-amalgamation-3.6.23.1
AUTOMAKE_$(CONFIG_USER_LUA) += lua-5.1.4

AUTOMAKE_$(CONFIG_USER_LUA_LUAROCKS) += luarocks-2.0.2

# make sure we do not do parallel builds
MAKEFLAGS := $(MAKEFLAGS) -j1

include $(ROOTDIR)/tools/automake.inc

LUAROCKS_CMD = LUAROCKS_CONFIG=`pwd`/config.lua \
					DESTDIR="$(ROMFSDIR)" \
					LUA_INIT="package.path='$(ROMFSDIR)/usr/share/lua/5.1//?.lua;$(ROMFSDIR)/usr/share/lua/5.1//?/init.lua;'" \
					LUA_INCDIR="$(ROMFSDIR)/usr/include" \
					LUA_LIBDIR="$(ROMFSDIR)/usr/lib" \
					LUA_BINDIR="/usr/bin/" \
					$(ROMFSDIR)/usr/bin/luarocks \
					--to=$(ROMFSDIR)/usr \
					CC="$(CC)" \
					CFLAGS="$(CFLAGS)" \
					LD="$(CC) $(CFLAGS) $(LDFLAGS)"

luarocks_romfs:
ifdef CONFIG_USER_LUA_ORBIT
	$(LUAROCKS_CMD) install orbit
endif
ifdef CONFIG_USER_LUA_LUASQL_SQLITE3
	$(LUAROCKS_CMD) install luasql-sqlite3
endif
ifdef CONFIG_USER_LUA_WSAPI
	$(LUAROCKS_CMD) install wsapi
endif
ifdef CONFIG_USER_LUA_WSAPI_XAVANTE
	$(LUAROCKS_CMD) install wsapi-xavante
endif
ifdef CONFIG_USER_LUA_XAVANTE
	$(LUAROCKS_CMD) install xavante
endif
ifdef CONFIG_USER_LUA_COSMO
	$(LUAROCKS_CMD) install cosmo
endif

