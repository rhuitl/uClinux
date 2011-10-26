

PROGRAMS = lircd lircmd irrecord
CC       += -I..
FLTFLAGS += -s 32000

HW = hw_default.o receive.o transmit.o

lircd_simsend_OBJECTS = lircd_simsend.o hw_default_simsend.o \
		config_file.o ir_remote.o receive.o transmit.o
lircd_simrec_OBJECTS = lircd_simrec.o hw_default_simrec.o \
		config_file.o ir_remote.o receive.o transmit.o
slinke_OBJECTS =  slinke.o config_file.o dump_config.o
irrecord_OBJECTS =  irrecord.o dump_config.o config_file.o ir_remote.o $(HW)
lircmd_OBJECTS =  lircmd.o
lircd_OBJECTS =  lircd.o ir_remote.o config_file.o $(HW)


all: $(PROGRAMS)

lircd: $(lircd_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(lircd_OBJECTS) $(LDLIBS)

slinke: $(slinke_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(slinke_OBJECTS) $(LDLIBS)

irrecord: $(irrecord_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(irrecord_OBJECTS) $(LDLIBS)

lircmd: $(lircmd_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(lircmd_OBJECTS) $(LDLIBS)

lircd.simsend: $(lircd_simsend_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(lircd_simsend_OBJECTS) $(LDLIBS)

lircd.simrec: $(lircd_simrec_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(lircd_simrec_OBJECTS) $(LDLIBS)

clean:
	rm -f *.o $(PROGRAMS) *.elf *.gdb


config_file.o: config_file.c ../config.h lircd.h ir_remote.h \
	../drivers/lirc.h config_file.h
dump_config.o: dump_config.c ../config.h dump_config.h ir_remote.h \
	../drivers/lirc.h config_file.h
hw_creative.o: hw_creative.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_creative.h
hw_default.o: hw_default.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h lircd.h receive.h transmit.h hw_default.h
hw_irman.o: hw_irman.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_irman.h
hw_logitech.o: hw_logitech.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_logitech.h
hw_pinsys.o: hw_pinsys.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_pinsys.h
hw_pixelview.o: hw_pixelview.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_pixelview.h
hw_silitek.o: hw_silitek.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h hw_silitek.h
hw_slinke.o: hw_slinke.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h serial.h lircd.h receive.h hw_slinke.h
irrecord.o: irrecord.c ../config.h ../drivers/lirc.h hardware.h \
	ir_remote.h dump_config.h config_file.h
ir_remote.o: ir_remote.c ../config.h ../drivers/lirc.h lircd.h \
	ir_remote.h hardware.h
lircd.o: lircd.c ../config.h lircd.h ir_remote.h ../drivers/lirc.h \
	config_file.h hardware.h
lircmd.o: lircmd.c ../config.h
receive.o: receive.c ../config.h hardware.h ../drivers/lirc.h \
	ir_remote.h lircd.h receive.h
serial.o: serial.c ../config.h lircd.h ir_remote.h ../drivers/lirc.h
transmit.o: transmit.c ../config.h lircd.h ir_remote.h ../drivers/lirc.h \
	transmit.h

lircd_simsend.o: lircd.c
	$(CC) $(CFLAGS) -DSIM_SEND -c lircd.c -o lircd_simsend.o
hw_default_simsend.o: hw_default.c
	$(CC) $(CFLAGS) -DSIM_SEND -c hw_default.c -o hw_default_simsend.o
lircd_simrec.o: lircd.c
	$(CC) $(CFLAGS) -DSIM_REC -c lircd.c -o lircd_simrec.o
hw_default_simrec.o: hw_default.c
	$(CC) $(CFLAGS) -DSIM_REC -c hw_default.c -o hw_default_simrec.o

