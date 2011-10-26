VERSION=0.5.1
CFLAGS += \
	  -DHAVE_LIBM=1 -DHAVE_LIBZ=1 \
	  -DHAVE_LIBPNG=1 \
	  -DHAVE_LIBJPEG=1 \
	  -DVIDEO_DEV=\"/dev/video\" -DDATDIR=\"/etc/config\"

LDFLAGS += -Wl,--export-dynamic

LIBS = -lpng -ljpeg -lz -lm -ldl

EXE = camserv.bin

all: $(EXE) libvideo_v4l.so libjpg_filter.so libtext_filter.so webcam.cgi

libvideo_v4l.so: video_v4l.o
	$(CC) -shared $(SH_LDFLAGS) -o $@ video_v4l.o $(SH_LDLIBS)

libvideo_basic.so: video_basic.o
	$(CC) -shared $(SH_LDFLAGS) -o $@ video_basic.o $(SH_LDLIBS)

libjpg_filter.so: jpg_filter.o
	$(CC) -shared $(SH_LDFLAGS) -o $@ jpg_filter.o $(SH_LDLIBS)

libtext_filter.so: text_filter.o
	$(CC) -shared $(SH_LDFLAGS) -o $@ text_filter.o $(SH_LDLIBS)

librand_filter.so: rand_filter.o
	$(CC) -shared $(SH_LDFLAGS) -o $@ rand_filter.o $(SH_LDLIBS)

OBJ = camconfig.o fixfont.o picture_loop.o \
		camserv.o jpgstuff.o video.o \
		filter.o main_loop.o shm.o \
		hash.o sock_field.o log.o modinfo.o sockset.o socket.o \
		list.o manager.o databuf.o grafxmisc.o

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS) $(LDLIBS$(LDLIBS_$@))

webcam.cgi: webcam.o camconfig.o hash.o log.o
	$(CC) $(LDFLAGS) -o $@ camconfig.o log.o hash.o webcam.o $(LIBS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) $(EXE) /bin/camserv
	if test ! -d $(ROMFSDIR)/lib/camserv; then \
	mkdir $(ROMFSDIR)/lib/camserv; fi
	$(ROMFSINST) libvideo_v4l.so /lib/camserv/libvideo_v4l.so
	$(ROMFSINST) libjpg_filter.so /lib/camserv/libjpg_filter.so
	$(ROMFSINST) libtext_filter.so /lib/camserv/libtext_filter.so
	$(ROMFSINST) camserv.cfg /etc/default/camserv.cfg
	$(ROMFSINST) webcam.cgi /home/httpd/cgi-bin/webcam

clean:
	rm -f *.o *.so $(EXE) webcam.cgi
