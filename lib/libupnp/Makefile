
.EXPORT_ALL_VARIABLES:

TARGET :=  # $(CROSS:-=)
DEBUG  := 0
TOOLS  := 1

CFLAGS += -fPIC

all:
	@cd upnp && $(MAKE)
	-@if [ ! -d ./upnp/inc/upnp ]; then mkdir ./upnp/inc/upnp; fi
	-@cp ./upnp/inc/* ./upnp/inc/upnp/

romfs:
	$(ROMFSINST) upnp/bin/$(TARGET)/libixml.so /lib 
	$(ROMFSINST) upnp/bin/$(TARGET)/libthreadutil.so /lib 
	$(ROMFSINST) upnp/bin/$(TARGET)/libupnp.so /lib

clean:
	@cd upnp && $(MAKE) clean
	-@cd ./upnp/inc; rm -rf ./upnp/* 
	-@rm -rf ./upnp/bin/$(TARGET)

