#! /bin/bash

LIRC_VERSION="0.6.3"

#############################################################################
## Default Values
COM1_PORT=0x3f8
COM2_PORT=0x2f8
COM3_PORT=0x3e8
COM4_PORT=0x2e8
COM1_IRQ=4
COM2_IRQ=3
COM3_IRQ=4
COM4_IRQ=3
LPT1_PORT=0x378
LPT2_PORT=0x278
LPT3_PORT=0x3bc
LPT1_IRQ=7
LPT2_IRQ=5
LPT3_IRQ=none

LIRC_DRIVER="serial"
LIRC_MAJOR=61
SELECTED_DRIVER=""
DRIVER_PARAMETER="com1"
SOFT_CARRIER="on"
TRANSMITTER="off"
TIMER=65536
X11_WINDOWS="on"
DEBUG="off"
NO_DAEMONIZE="off"
NO_LONG_CODES="off"
USE_SYSLOG="off"

#############################################################################
## Variables
BACKTITLE="LIRC $LIRC_VERSION Configuration"
TEMP=".setup.tmp"
CONFIG=".setup.config"
START="configure.sh"
CONFIGURE=no

MAIN_MENU_TEXT="Welcome to the LIRC Configuration Menu. Here you"
MAIN_MENU_TEXT="$MAIN_MENU_TEXT can configure the driver and some compile-time"
MAIN_MENU_TEXT="$MAIN_MENU_TEXT settings for LIRC applications."
CONFIG_DRIVER_TEXT="Please select a driver, that supports your hardware."
CONFIG_SOFTWARE_TEXT="Here you can change some compile-time settings for LIRC applications"
SET_PORT_TEXT="Either choose a predefined IO Port/IRQ combination, or enter costum values"
SET_PORT_TEXT="$SET_PORT_TEXT Hint: use <Space> to choose and <Enter> to proceed"
SET_TTY_TEXT="Choose the tty where your hardware is available."
GET_PORT_TEXT="Enter the IO port followed with a space and the IRQ (none for no IRQ)"

#############################################################################
## Functions
function GetSelectedDriver
    {
    COM1="off"; COM2="off"; COM3="off"; COM4="off"
    LPT1="off"; LPT2="off"; LPT3="off"; USER="off"
    IRTTY="none"
    if   test "$DRIVER_PARAMETER" = "com1"; then COM1="on"; LIRC_PORT=$COM1_PORT; LIRC_IRQ=$COM1_IRQ
    elif test "$DRIVER_PARAMETER" = "com2"; then COM2="on"; LIRC_PORT=$COM2_PORT; LIRC_IRQ=$COM2_IRQ
    elif test "$DRIVER_PARAMETER" = "com3"; then COM3="on"; LIRC_PORT=$COM3_PORT; LIRC_IRQ=$COM3_IRQ
    elif test "$DRIVER_PARAMETER" = "com4"; then COM4="on"; LIRC_PORT=$COM4_PORT; LIRC_IRQ=$COM4_IRQ
    elif test "$DRIVER_PARAMETER" = "tty1"; then COM1="on"; IRTTY="/dev/ttyS0"; LIRC_PORT="none"; LIRC_IRQ="none"
    elif test "$DRIVER_PARAMETER" = "tty2"; then COM2="on"; IRTTY="/dev/ttyS1"; LIRC_PORT="none"; LIRC_IRQ="none"
    elif test "$DRIVER_PARAMETER" = "tty3"; then COM3="on"; IRTTY="/dev/ttyS2"; LIRC_PORT="none"; LIRC_IRQ="none"
    elif test "$DRIVER_PARAMETER" = "tty4"; then COM4="on"; IRTTY="/dev/ttyS3"; LIRC_PORT="none"; LIRC_IRQ="none"
    elif test "$DRIVER_PARAMETER" = "lpt1"; then LPT1="on"; LIRC_PORT=$LPT1_PORT; LIRC_IRQ=$LPT1_IRQ
    elif test "$DRIVER_PARAMETER" = "lpt2"; then LPT2="on"; LIRC_PORT=$LPT2_PORT; LIRC_IRQ=$LPT2_IRQ
    elif test "$DRIVER_PARAMETER" = "lpt3"; then LPT3="on"; LIRC_PORT=$LPT3_PORT; LIRC_IRQ=$LPT3_IRQ
    elif test "$DRIVER_PARAMETER" = "none"; then LIRC_PORT="none"; LIRC_IRQ="none"
    elif test "$DRIVER_PARAMETER" = "user"; then USER="on"
    fi

    SELECTED_DRIVER="driver:$LIRC_DRIVER"
    if test "$LIRC_PORT" != "none"; then SELECTED_DRIVER="$SELECTED_DRIVER io:$LIRC_PORT"; fi
    if test "$LIRC_IRQ"  != "none"; then SELECTED_DRIVER="$SELECTED_DRIVER irq:$LIRC_IRQ"; fi
    if test "$IRTTY" != "none"; then SELECTED_DRIVER="$SELECTED_DRIVER tty:$IRTTY"; fi
    }



function GetPortAndIrq
    {
    dialog --clear --backtitle "$BACKTITLE" \
           --title "Enter IO Port and IRQ" \
           --inputbox "$GET_PORT_TEXT" 9 74 "$LIRC_PORT $LIRC_IRQ" \
           2> $TEMP
    if test "$?" = "0"; then
        {
	set `cat $TEMP`
        LIRC_PORT=$1
        LIRC_IRQ=$2
        }
    fi
    }


function SetPortAndIrq
    {
    if test "$LIRC_DRIVER" = "serial" -o \
	    "$LIRC_DRIVER" = "sir" -o \
	    "$LIRC_DRIVER" = "tekram" -o \
	    "$LIRC_DRIVER" = "packard_bell" -o \
	    "$LIRC_DRIVER" = "animax" -o \
	    "$LIRC_DRIVER" = "irdeo"; then
        {
        dialog --clear --backtitle "$BACKTITLE" \
               --title "Specify port and IRQ of your hardware" \
               --radiolist "$SET_PORT_TEXT" 13 74 6 \
                 1 "COM1 ($COM1_PORT, $COM1_IRQ)" $COM1 \
                 2 "COM2 ($COM2_PORT, $COM2_IRQ)" $COM2 \
                 3 "COM3 ($COM3_PORT, $COM3_IRQ)" $COM3 \
                 4 "COM4 ($COM4_PORT, $COM4_IRQ)" $COM4 \
                 9 "Other (costum values)" $USER \
               2> $TEMP
        if test "$?" = "0"; then
            {
	    set `cat $TEMP`
            if   test "$1" = "1"; then DRIVER_PARAMETER="com1"
            elif test "$1" = "2"; then DRIVER_PARAMETER="com2"
            elif test "$1" = "3"; then DRIVER_PARAMETER="com3"
            elif test "$1" = "4"; then DRIVER_PARAMETER="com4"
            elif test "$1" = "9"; then DRIVER_PARAMETER="user"; GetPortAndIrq
            fi
            GetSelectedDriver
            }
        fi
        }
    elif test "$LIRC_DRIVER" = "parallel"; then
        {
        dialog --clear --backtitle "$BACKTITLE" \
               --title "Specify port and IRQ of your hardware" \
               --radiolist "$SET_PORT_TEXT" 13 74 6 \
                 1 "LPT1 ($LPT1_PORT, $LPT1_IRQ)" $LPT1 \
                 2 "LPT2 ($LPT2_PORT, $LPT2_IRQ)" $LPT2 \
                 3 "LPT3 ($LPT3_PORT, $LPT3_IRQ)" $LPT3 \
                 9 "Other (costum values)" $USER \
                 2> $TEMP
        if test "$?" = "0"; then
            {
	    set `cat $TEMP`
            if   test "$1" = "1"; then DRIVER_PARAMETER="lpt1"
            elif test "$1" = "2"; then DRIVER_PARAMETER="lpt2"
            elif test "$1" = "3"; then DRIVER_PARAMETER="lpt3"
            elif test "$1" = "9"; then DRIVER_PARAMETER="user"; GetPortAndIrq
            fi
            GetSelectedDriver
            }
        fi
        }
    elif test "$LIRC_DRIVER" = "remotemaster" -o "$LIRC_DRIVER" = "irman" -o \
	"$LIRC_DRIVER" = "logitech" -o "$LIRC_DRIVER" = "pctv" -o \
	"$LIRC_DRIVER" = "creative" -o "$LIRC_DRIVER" = "slinke" -o \
        "$LIRC_DRIVER" = "silitek" -o "$LIRC_DRIVER" = "realmagic"; then
	{
        dialog --clear --backtitle "$BACKTITLE" \
               --title "Select tty to use" \
               --radiolist "$SET_TTY_TEXT" 13 74 6 \
                 1 "COM1 (/dev/ttyS0)" $COM1 \
                 2 "COM2 (/dev/ttyS1)" $COM2 \
                 3 "COM3 (/dev/ttyS2)" $COM3 \
                 4 "COM4 (/dev/ttyS3)" $COM4 \
               2> $TEMP
	}
        if test "$?" = "0"; then
            {
	    set `cat $TEMP`
            if   test "$1" = "1"; then DRIVER_PARAMETER="tty1"
            elif test "$1" = "2"; then DRIVER_PARAMETER="tty2"
            elif test "$1" = "3"; then DRIVER_PARAMETER="tty3"
            elif test "$1" = "4"; then DRIVER_PARAMETER="tty4"
            fi
            GetSelectedDriver
            }
        fi
    fi
    }



function DriverOptions
    {
    if   test "$LIRC_DRIVER" = "serial"; then
        {
        dialog --clear --backtitle "$BACKTITLE" \
               --title "Driver specific Options" \
               --checklist "" 14 74 5 \
                 1 "With transmitter diode" $TRANSMITTER \
                 2 "Software generated carrier" $SOFT_CARRIER \
               2> $TEMP
        if test "$?" = "0"; then
            {
	    set -- `cat $TEMP`
            SOFT_CARRIER="off"
	    TRANSMITTER="off"
            for ITEM in $@; do
                {
                if   test $ITEM = "\"1\""; then TRANSMITTER="on";
                elif test $ITEM = "\"2\""; then SOFT_CARRIER="on";
                fi
                }
            done
	    if test "$TRANSMITTER" = "off"; then SOFT_CARRIER="off"; fi
            }
        fi
        }
    elif test "$LIRC_DRIVER" = "parallel"; then
        {
        dialog --clear --backtitle "$BACKTITLE" \
               --title "Driver specific Options" \
               --inputbox "Timer value for parallel port driver" 9 74 "$TIMER" \
               2> $TEMP
        if test "$?" = "0"; then
            {
	    set `cat $TEMP`
            TIMER=$1
            }
        fi
        }
    fi
    }

function ConfigDriver
    {
    dialog --clear --backtitle "$BACKTITLE" \
           --title "Select your driver" \
           --menu "$CONFIG_DRIVER_TEXT" 14 74 6 \
             1 "Home-brew (16x50 UART compatible serial port)" \
             2 "Home-brew (parallel port)" \
	     3 "Other serial port devices" \
	     4 "TV card" \
             5 "SIR IrDA (built-in IR ports)" \
	     6 "None (network connections only)" 2> $TEMP

    if test "$?" = "0"; then
        {
	set `cat $TEMP`
        if   test "$1" = "1"; then LIRC_DRIVER=serial;   DRIVER_PARAMETER=com1;
        elif test "$1" = "2"; then LIRC_DRIVER=parallel; DRIVER_PARAMETER=lpt1;
        elif test "$1" = "3"; then
	    # "Other serial port devices"
	    dialog --clear --backtitle "$BACKTITLE" \
                --title "Select your driver" \
		--menu "$CONFIG_DRIVER_TEXT" 18 74 12 \
			1 "Anir Multimedia Magic" \
			2 "CARACA" \
			3 "Creative Infra Receiver" \
			4 "IRdeo" \
			5 "Irman / UIR" \
			6 "Logitech/AST" \
			7 "Miro PCTV receiver" \
			8 "Packard Bell receiver" \
			9 "Pinnacle Systems PCTV (pro) receiver" \
			0 "PixelView RemoteMaster RC2000/RC3000" \
			a "REALmagic (bundled with Hollywood Plus DVD card)" \
			b "Slink-e" \
                        c "Silitek SM-1000" \
			d "Tekram Irmate 210 (16x50 UART compatible serial port)" 2> $TEMP;
	    if test "$?" = "0"; then
		{
		set `cat $TEMP`
		if   test "$1" = "1"; then LIRC_DRIVER=animax;       DRIVER_PARAMETER=com1;
		elif test "$1" = "2"; then LIRC_DRIVER=caraca;       DRIVER_PARAMETER=tty1;
		elif test "$1" = "3"; then LIRC_DRIVER=creative;     DRIVER_PARAMETER=tty1;
		elif test "$1" = "4"; then LIRC_DRIVER=irdeo;        DRIVER_PARAMETER=com1;
		elif test "$1" = "5"; then LIRC_DRIVER=irman;        DRIVER_PARAMETER=tty1;
		elif test "$1" = "6"; then LIRC_DRIVER=logitech;     DRIVER_PARAMETER=tty1;
		elif test "$1" = "7"; then LIRC_DRIVER=pctv;         DRIVER_PARAMETER=tty1;
		elif test "$1" = "8"; then LIRC_DRIVER=packard_bell; DRIVER_PARAMETER=com1;
		elif test "$1" = "9"; then LIRC_DRIVER=pctv;         DRIVER_PARAMETER=tty1;
		elif test "$1" = "0"; then LIRC_DRIVER=remotemaster; DRIVER_PARAMETER=tty1;
		elif test "$1" = "a"; then LIRC_DRIVER=realmagic;    DRIVER_PARAMETER=tty1;
		elif test "$1" = "b"; then LIRC_DRIVER=slinke;       DRIVER_PARAMETER=tty3;
		elif test "$1" = "c"; then LIRC_DRIVER=silitek;      DRIVER_PARAMETER=tty1;
		elif test "$1" = "d"; then LIRC_DRIVER=tekram;       DRIVER_PARAMETER=com1;
		fi
		}
	    else
		return;
	    fi;

        elif test "$1" = "4"; then
	    dialog --clear --backtitle "$BACKTITLE" \
                --title "Select your driver" \
		--menu "$CONFIG_DRIVER_TEXT" 18 74 12\
                        1 "Askey Magic TView CPH03x (card=1)" \
			2 "Askey/Typhoon/Anubis Magic TView CPH051/061 (bt878) (card=24)" \
			3 "AverMedia TV card (TVCapture, TVPhone) (card=6)" \
			4 "AverMedia TV card (TVCapture98, TVPhone98) (card=13/41)" \
			5 "BestBuy Easy TV (card=55)" \
			6 "Chronos Video Shuttle II (card=35)" \
                        7 "Dynalink Magic TView (card=48)" \
			8 "Fly98 TV card" \
			9 "Hauppauge TV card (new I2C layer required)" \
			0 "Phoebe Tv Master + FM (card=22)" \
                        a "Pixelview PlayTV pro (card=37)" \
                        b "Pixelview PlayTV (bt878) (Prolink PV-BT878P+, card=16)" \
			c "Prolink PV-BT878P+4E (PixelView PlayTV PAK) (card=50)" \
			d "ProVideo PV951 (card=42)" \
			e "Technisat MediaFocus I" \
			f "TView99 CPH063 (card=38)" 2> $TEMP;

	    if test "$?" = "0"; then
		{
		set `cat $TEMP`
		if   test "$1" = "1"; then LIRC_DRIVER=cph03x;          DRIVER_PARAMETER=none;
		elif test "$1" = "2"; then LIRC_DRIVER=cph06x;          DRIVER_PARAMETER=none;
		elif test "$1" = "3"; then LIRC_DRIVER=avermedia;       DRIVER_PARAMETER=none;
		elif test "$1" = "4"; then LIRC_DRIVER=avermedia98;     DRIVER_PARAMETER=none;
		elif test "$1" = "5"; then LIRC_DRIVER=bestbuy;		DRIVER_PARAMETER=none;
		elif test "$1" = "6"; then LIRC_DRIVER=chronos;         DRIVER_PARAMETER=none;
		elif test "$1" = "7"; then LIRC_DRIVER=cph03x;          DRIVER_PARAMETER=none;
		elif test "$1" = "8"; then LIRC_DRIVER=fly98;           DRIVER_PARAMETER=none;
		elif test "$1" = "9"; then LIRC_DRIVER=hauppauge;       DRIVER_PARAMETER=none;
		elif test "$1" = "0"; then LIRC_DRIVER=cph06x;          DRIVER_PARAMETER=none;
		elif test "$1" = "a"; then LIRC_DRIVER=pixelview_pro;   DRIVER_PARAMETER=none;
		elif test "$1" = "b"; then LIRC_DRIVER=pixelview_bt878; DRIVER_PARAMETER=none;
		elif test "$1" = "c"; then LIRC_DRIVER=pixelview_pak;   DRIVER_PARAMETER=none;
		elif test "$1" = "d"; then LIRC_DRIVER=provideo;        DRIVER_PARAMETER=none;
		elif test "$1" = "e"; then LIRC_DRIVER=mediafocusI;     DRIVER_PARAMETER=none;
		elif test "$1" = "f"; then LIRC_DRIVER=cph06x;          DRIVER_PARAMETER=none;
		fi
		}
	    else
		return;
	    fi;
        elif test "$1" = "5"; then LIRC_DRIVER=sir;          DRIVER_PARAMETER=com3;
        elif test "$1" = "6"; then LIRC_DRIVER=none;         DRIVER_PARAMETER=none;
    fi
        GetSelectedDriver
        SetPortAndIrq
        DriverOptions
        }
    fi
    }



function ConfigSoftware
    {
    dialog --clear --backtitle "$BACKTITLE" \
           --title "Software Configuration" \
           --checklist "$CONFIG_SOFTWARE_TEXT" 12 74 5 \
             1 "Compile tools for X-Windows" $X11_WINDOWS \
             2 "Compile with DEBUG code" $DEBUG \
             3 "Disable daemonize" $NO_DAEMONIZE \
             4 "Disable long codes" $NO_LONG_CODES \
             5 "Use syslogd instead of own log-file" $USE_SYSLOG 2>$TEMP

    if test "$?" = "0"; then
        {
	set -- `cat $TEMP`
        X11_WINDOWS="off"; DEBUG="off"; NO_DAEMONIZE="off"; NO_LONG_CODES="off"
        USE_SYSLOG="off"
        for ITEM in $@; do
            {
            if   test $ITEM = "\"1\""; then X11_WINDOWS="on"
            elif test $ITEM = "\"2\""; then DEBUG="on"
            elif test $ITEM = "\"3\""; then NO_DAEMONIZE="on"
            elif test $ITEM = "\"4\""; then NO_LONG_CODES="on"
            elif test $ITEM = "\"5\""; then USE_SYSLOG="on"
            fi
            }
        done
        }
    fi
    }



function SaveConfig
    {
    echo "LIRC_DRIVER=$LIRC_DRIVER" >$CONFIG
    echo "LIRC_PORT=$LIRC_PORT" >>$CONFIG
    echo "LIRC_IRQ=$LIRC_IRQ" >>$CONFIG
    echo "LIRC_MAJOR=$LIRC_MAJOR" >>$CONFIG
    echo "IRTTY=$IRTTY" >>$CONFIG
    echo "DRIVER_PARAMETER=$DRIVER_PARAMETER" >>$CONFIG
    echo "SOFT_CARRIER=$SOFT_CARRIER" >>$CONFIG
    echo "TRANSMITTER=$TRANSMITTER" >>$CONFIG
    echo "TIMER=$TIMER" >>$CONFIG
    echo "X11_WINDOWS=$X11_WINDOWS" >>$CONFIG
    echo "DEBUG=$DEBUG" >>$CONFIG
    echo "NO_DAEMONIZE=$NO_DAEMONIZE" >>$CONFIG
    echo "NO_LONG_CODES=$NO_LONG_CODES" >>$CONFIG
    echo "USE_SYSLOG=$USE_SYSLOG" >>$CONFIG
    chmod 666 $CONFIG

    echo '#!/bin/bash' >$START
    echo >>$START
    echo "./configure \\" >>$START
    echo "--with-module-dir=/lib/modules/`uname -r`/misc \\" >>$START
    if   test "$LIRC_DRIVER" = "serial"; then
        {
        if test "$SOFT_CARRIER" = "off"; then echo "--without-soft-carrier \\" >>$START; fi
        if test "$TRANSMITTER" = "on"; then echo "--with-transmitter \\" >>$START; fi
        }
    elif test "$LIRC_DRIVER" = "parallel"; then
        {
        if test "$TIMER" != "0"; then echo "--with-timer=$TIMER \\" >>$START;
	else echo "--without-timer \\" >>$START;
	fi
        }
    elif test "$LIRC_DRIVER" = "irman" -o "$LIRC_DRIVER" = "remotemaster" -o \
	"$LIRC_DRIVER" = "logitech" -o "$LIRC_DRIVER" = "pctv" -o \
	"$LIRC_DRIVER" = "slinke" -o "$LIRC_DRIVER" = "silitek" -o \
        "$LIRC_DRIVER" = "realmagic"; then
        {
	echo "--with-tty=$IRTTY \\" >>$START
	}
    fi
    if test "$X11_WINDOWS" = "on"; then echo "--with-x \\" >>$START; fi
    if test "$DEBUG" = "on"; then echo "--enable-debug \\" >>$START; fi
    if test "$NO_DAEMONIZE" = "on"; then echo "--disable-daemonize \\" >>$START; fi
    if test "$NO_LONG_CODES" = "on"; then echo "--disable-long-codes \\" >>$START; fi
    if test "$USE_SYSLOG" = "on"; then echo "--with-syslog \\" >>$START; fi
    echo "--with-driver=$LIRC_DRIVER \\" >>$START
    echo "--with-major=$LIRC_MAJOR \\" >>$START
    echo "--with-port=$LIRC_PORT \\" >>$START
    echo "--with-irq=$LIRC_IRQ \\" >>$START
    echo "\"\$@\"" >>$START
    chmod 755 $START

    MESSAGE="Configuration: $CONFIG, executable shell script: $START"
    EXIT="yes"
    }

#############################################################################
## Main Program
if ! which dialog >/dev/null; then
    echo "dialog not found!"
    exit 1
fi

if test -f $CONFIG; then
    {
    echo "Loading saved configuration from $CONFIG"
    source $CONFIG
    sleep 1
    }
fi
EXIT="no"
MESSAGE="Abnormal Termination"
GetSelectedDriver
while test "$EXIT" != "yes"; do
    {
    dialog --clear --backtitle "$BACKTITLE" \
           --title "Mainmenu" \
           --menu "$MAIN_MENU_TEXT" 14 74 5 \
             1 "Driver configuration ($SELECTED_DRIVER)" \
             2 "Software configuration" \
             3 "Save configuration & run configure" \
             4 "Save configuration & exit" \
             5 "Exit WITHOUT doing anything" 2>$TEMP

    if test "$?" != "0"; then
        {
        MESSAGE="Configuration cancelled!"
        EXIT="yes"
        }
    else
        {
	set `cat $TEMP`
        if test "$1" = "1"; then ConfigDriver
        elif test "$1" = "2"; then ConfigSoftware
        elif test "$1" = "3"; then
            {
            SaveConfig
            CONFIGURE="yes"
            }
        elif test "$1" = "4"; then SaveConfig
        elif test "$1" = "5"; then
            {
            MESSAGE="Configuration NOT saved!"
            EXIT=yes
            }
        fi
        }
    fi
    }
done
#clear
rm -f $TEMP
echo "Written by <karsten.scheibler@bigfoot.de>, 1999-JUN-28"
echo
echo $MESSAGE
if test "$CONFIGURE" = "yes"; then
    {
    echo "Starting the generated shell script which will call configure with the right"
    echo "parameters..."
    ./$START
    }
fi
## EOF ######################################################################

