/*
*++ horch - simple CAN bus analyzer
*-- horch - einfacher CAN Bus Analyzer
 *
 * Copyright (c) 1999-2001 port GmbH, Halle
 *------------------------------------------------------------------
 * $Header: /cvs/sw/new-wave/user/horch/horch.c,v 1.2 2007-04-04 05:20:33 gerg Exp $
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log: horch.c,v $
 * Revision 1.2  2007-04-04 05:20:33  gerg
 * #10381
 *
 * Little changes to make horch listen to the CAN
 *
 * Patch submitted by Thomas Brinker <tb@emlix.com>
 *
 * Revision 1.1  2003/07/18 00:11:46  gerg
 * I followed as much rules as possible (I hope) and generated a patch for the
 * uClinux distribution. It contains an additional driver, the CAN driver, first
 * for an SJA1000 CAN controller:
 *   uClinux-dist/linux-2.4.x/drivers/char/can4linux
 * In the "user" section two entries
 *   uClinux-dist/user/can4linux     some very simple test examples
 *   uClinux-dist/user/horch         more sophisticated CAN analyzer example
 *
 * Patch submitted by Heinz-Juergen Oertel <oe@port.de>.
 *
 *
 *
*/

/*
* SYNOPSIS
*
* .CS
* \fBhorch\fR [dtSTV] [-D dev][-b baud][-c id][-l file][-p port]
* .CE
* .nf
* .ta 1i
* .nf
*-- Aufrufargumente
*++ Command line options
* .CS
*--     -a        - advanced - benutzt \"baud\" als BTR0/1 Wert
*--     -b baud   - Baudrate für CAN (in KBit/s, Standard 125)
*--     -c<id>    - Benutzung der CAN id als Debug-ID
*--     -d        - Debug Mode, nützlich für Programmentwicklung
*--     -f<spec>  - Spezifikation für Empfangsfilter
*--     -l<file>  - Dateiname für lokales Aufzeichnen, Aktivierung mit 'l'
*--     -p<n>     - benutze Portnummer n im Servermode, Standard 7235
*--     -t        - Anzeige von Zeitstempeln beim Start
*--     -C        - interpretiere die -c CAN Message als Debug Message
*--     -D device - CAN Geräte Name, (z.B can1 (LINUX); 0..2 (Level-X))
*--     -S        - TCP/IP Server Mode
*--     -u        - benutzt UDP
*--     -T        - Benutzen der Betriebssystemzeit statt Treiber-Zeit
*--     -V        - Version
* .br
*++     -a        - advanced - use \"baud\" as BTR0/1 value
*++     -b baud   - use this baud rate at CAN (in KBit/s, Standard 125)
*++     -c<id>    - use id as debug id
*++     -d        - debug mode, useful for program developer
*++     -f<spec>  - specification for receive message filter
*++     -l<file>  - Logfilename, logging is enabled/disabled with 'l'
*++     -p<n>     - use portnumber in Servermode, default 7235
*++     -t        - show time stamp at start up
*++     -C        - interpret message id given with -c as debug message
*++     -D device - CAN device Name, (z.B can1 (LINUX); 0..3 (Level-X Channel))
*++     -S        - TCP/IP Server Mode
*++     -u        - use UDP
*++     -T        - use OS time not drivers time stamp
*++     -V        - Version
* .CE
* .LP
*.\".CS
*--.\"zusätzlich beim EtherCAN
*++.\"additional for EtherCAN
*++.\"    -C        - occupy console focus
*--.\"    -C        - Console Focus auf horch
*.\".CE
* .LP
* .CS
*-- zusätzlich beim LevelX 
*++ additional for LevelX 
*++     -B        - board name (see horch -h) 
*++     -U        - board number (e.g. 1..4 COM port)
*--     -B        - Board Name (siehe horch -h)  
*--     -U        - Board Nummer (z.B. 1..4 COM Port)
* .CE
*
*
*++ DESCRIPTION
*-- BESCHREIBUNG
*
* Version 2.4p1
* .sp
* .B horch
*++ is a command line application that is capable of receiving
*++ CAN messages and displaying them in a console window.
*++ Because the receiving of CAN messages 
*++ depends on a special hardware, the application is divided in the two parts,
*++ hardware dependend and console specific.
*-- ist eine Kommandozeilen Anwendung die in der Lage ist, CAN Nachrichten
*-- zu empfangen und in einem Konsolenfenster anzuzeigen.
*-- Der Empfang von CAN Nachrichten ist hardwareabhängig.
*-- Die 
*-- .B horch
*-- Anwendung gliedert sich deshalb in zwei Teile,
*-- einen hardwareabhängigen zum CAN Empfang
*-- und eine Konsolenanwendung.
* .LP
*++ The hardware layer can be a direct interface routine to a CAN controller
*++ or a operating system device driver.
*-- Die Hardwareschicht kann ein direktes Interface zum CAN Kontroller
*-- als auch ein Betriebssystem Treiber sein.
* .LP
*++ The console application part is used to configure
*++ the application and shows the received CAN message in different formats.
*++ Display formats are selectable on-line via control characters
*++ typed at stdin.
*-- Die Konsolenanwendung dient zur Konfiguration und zeigt die empfangenen
*-- CAN Nachrichten in verschiedenen Formaten an.
*-- Die Anzeigeformate sind zur Laufzeit über Kommandos
*-- am Standardeingabekanal wählbar.
* .LP
*++ In the
*++ .B "Server Mode"
*++ .B horch
*++ acts as a TCP/IP server waiting for a client that connects to it.
*++ It can bee seen that stdin and stdout are served by the TCP/IP connection. 
*-- In der
*-- .B Server -Betriebsart
*-- wartet
* .B horch
*-- auf Verbindungsaufnahme von Clients über TCP/IP.
*-- Die weiteren Ausführungen können so  betrachtet werden,
*-- als ob
*-- .B stdin
*-- und
*-- .B stdout
*-- über die TCP/IP Verbindung ersetzt werden.
*++ .LP
*++ The EtherCAN version of
*++ .B horch
*++ shows an established client connection by switching
*++ .B "Status 1"
*++ LED on.
*-- Eine Clientverbindung zu
*-- .B horch
*-- wird beim EtherCAN durch einschalten der
*-- .B "Status 1" -LED
*-- angezeigt.
* .LP
*++ A special message ID, ( -c message) can be used as a debug Message
*++ when developing embedded CAN applications.
*++ It's contents is displayed as text string.
*++ CAN devices that have no serial out for debug information can
*++ use CAN via the function 
*++ debug_print_can(unsigned char level, char *fmt, ...);
*-- Eine bestimmte Message-ID, änderbar mit
*-- \fB-c \fP\fIID\fP
*-- wird als Debug-Nachricht interpretiert.
*-- Sie enthält einen fortlaufenden Zeichenstrom, welcher als
*-- Text dargestellt wird.
*-- CAN Geräte, die keinen seriellen Ausgabekanal haben,
*-- könne über CAN mit der Funktion
*-- debug_print_can(unsigned char level, char *fmt, ...);
*-- formatierte Texte ausgeben.
*
*++ OPTIONS
*-- OPTIONEN
*
* .TP
* -a
*-- Wenn aggegeben, dann wird der mit -b \baud\" übergebeen Wert
*-- Als Inhalt der zwei Byte-Register BTR0 und BTR1 verwendet.
*-- Das niederwertige Byte entspricht BTR0.
*++ If specified, the \"baud\" value given with -b is used to set directly
*++ the bit-timing registers BTR0 and BTR1.
*++ Low byte is used for BTR0.
* .CS
* horch -ab 0x13c
* .CE
*-- Geht mit CPC-Treiber, auch EtherCAN, und can4linux.
*++ Implemented for CPC-Driver, EtherCAN, and can4linux.
* .TP
* -b baud
*-- verwendete Bit-Rate in KBaud.
*++ used baud rate in Kbaud.
*-- .br
*-- Fehlt diese Angabe, wird der Treiber
*-- mit dem Wert aus
*-- .I /proc/sys/Can/Baud
*-- geöffnet (LINUX can4linux).
*++ Without this option
*++ the driver is opened with the value from the file
*++ .I /proc/sys/Can/Baud
*++ (LINUX can4linux)
* .IP -d
*-- Debugmode einschalten
*++ Switch debug mode on
* .br
*-- Es erfolgen Ausschriften auf
*-- .B stderr ,
*-- welche In\%for\%ma\%tionen zum Programmablauf
*-- und zu internen Zuständen geben.
*++ Messages about internal states and program flow
*++ are printed to
*++ .B stderr .
* .TP
* -C
* .TP
* -c CAN-ID
*-- Die als Argument zur Option -c angegebene CAN-Message-ID
*-- wird besonders interpretiert, wenn die Option -C gesetzt ist.
*-- Ihr Inhalt wird als ASCII-Zeichenstrom ausgewertet und angezeigt. 
*-- CAN Applikationen haben damit die Möglichkeit Textmeldungen,
*-- z.B. Debugging-Meldungen, über CAN abzusetzen.
*++ The CAN message ID given as an argument to the -c option
*++ gets a special interpretation if the option -C is set.
*++ It's content is interpretet and displayed as an ASCII character stream.
*++ CAN applications gets the opportunity to send text messages,
*++ e.g. debugging messages via CAN.
* .TP
*-- -f <Filter Spezifikation>
*++ -f <filter specification>
*-- Filter für Receive Messages
*++ Use a filter for all received messages
* .sp
*-- Ein Filter für Empfangsnachrichten wird installiert.
*-- Es können variable Bereiche angegeben werden,
*-- welche das Filter beim Empfang passieren.
*++ This option/command installs a filter for receive messages.
*++ Only messages passing the filter are displayed.
*++ It is possible to specify mor then one filter area.
* .sp
* .CS
* f 10,20,100-200,0x3e8-0x640
* .CE
*--Zwischen den Zahlen und Kommas dürfen keine Leerzeichen stehen.
*++Spaces are not allowed between numbers and comma.
*-- Default ist:
*++ The default installed filter description is:
* .sp
* .CS
* f 0-536870911
* .CE
*-- für alle Nachrichten (29 bit id).
*++ for receiving all messages (29 bit id).
.\" max 50 Bereiche definierbar, siehe filter.h  MAX_RANGE
* .TP
* -l filename
*-- Die formatierten Ausgaben können in einer Log-Datei
*-- lokal gespeichert werden.
*-- Der Standard Dateiname ist
*-- .B logfile .
*-- Mit dieser Option kann er geändert werden.
*-- Die Aktivierung der Aufzeichnung erfolgt mit einem interaktiven Kommando
*-- (siehe dort).
*-- .br
*-- Logfiles werden nicht im Server Mode angelegt.
*++ The formatted display output can be saved in a local file.
*++ It's default name is
*++ .B logfile .
*++ With this option it is possible to set a new log-file name.
*++ Logging is activated sending a interactive command (see there) to
*++ .B horch .
*++ .br
*++ Logfiles are not created in Server mode.
* .TP
* -p port
*-- Das Internetprotokoll benutzt
*-- .B Portnummer n
*-- um einen bestimmten Dienst auf einem Server zu erreichen.
*-- Für
*-- .B horch
*-- ist das die Portnummer 7235.
*-- Sie kann mit dieser Option beim Start festgelegt werden.
*++ The internet protocol uses the
*++ .B "port number"
*++ to address a specific service on an server host.
*++ This is port number 7235 for
*++ .B horch .
*++ The port number can be set at at start time with this option.
* .TP
* -s time
*-- Ausgabe der CAN Contoller Statusinformationen aller <time> ms.
*++ Display CAN controller status information every <time> ms.
* .TP
* -t
*-- Standardmäßig ist die Ausgabe des Zeitstempels beim Start deaktiviert
*-- und kann interaktiv freigegeben werden.
*-- Die Angabe dieser Option gibt die Ausgabe von Beginn an frei.
*++ By default displaying of the time stamp is disabled at start up.
*++ It can be enabled interactively.
*++ With this option given, it is enabled at start up.
*.\" .TP
*.\" -C
*--.\" Belege Console.
*--.\" .br
*--.\" Beim Start auf dem EtherCAN Modul bekommt
*--.\" .B horch
*--.\" die Konsole für Ein-Ausgaben zugeteil.
*++.\" occupy console focus
*++.\" .br
*++.\" When starting
*++.\" .B horch
*++.\" on the EtherCAN
*++.\" the console in/output is occupied by
*++.\" .B horch .
* .TP
* -D dev
*-- Auswahl des verwendeten CAN Kanals (LINUX und Windows Treiber).
*-- .B dev
*-- ist der verwendete Devicename und wird als /dev/<\fBdev\fR>
*-- verwendet.
*-- Voraussetzung ist ein installierter LINUX CAN-Devicetreiber.
*++ Select the CAN channel to be used (LINUX).
*++ .B dev
*++ is the device name and is used as /dev/<\fBdev\fR> .
*++ Precondition is a installed LINUX CAN device driver.
* .TP
* -S
*-- Betrieb von
*-- .B horch
*-- im TCP/IP Server-Mode.
*++ Using
*++ .B horch
*++ in the TCP/IP server mode.
* .br
*-- Der Server kann am lokalen Rechner als
*-- .I localhost
*-- oder innerhalb eines TCP/IP Netzwerkes mit der Portnummer 7235
*-- erreicht werden.
*++  This server is reachable within the local host as
*++ .I localhost ,
*++ or within a TCP/IP network with the name of the
*++ hosted computer and the port number 7235.
*-- Alle Kommandos stehen über Socket Streams zur Verfügung.
*++ All commands to
*++ .B horch
*++ can be given over socket streams.
*-- .br
*-- Für Kommandobetrieb
*-- kann der Server auch über
*-- .B Telnet
*++ For the command mode
*++ the server can also be reached 
*++ with the common
*++ .B telnet
*++ application.
* .sp
* .CS
* telnet host 7235
* .CE
*-- erreicht werden.
* .br
*-- Telnet  sollte im "character" Mode betrieben werden.
*-- Dadurch werden Kommandos sofort wirksam.
*++ Telnet should be used with "charcter mode".
*++ In this mode commands are getting immediately effective.
* .CS
* telnet> mode character
* .CE
* .TP
* -T
*-- Benutze Betriebssytem Zeit als Zeitstempel.
*-- .br
*-- Standardmäßig benutzt
*-- .B horch
*-- den Zeitstempel vom CAN Treiber, welcher den Empfangszeitpunkt
*-- wiederspiegelt.
*-- Kann der Treiber keinen Zeitstempel liefern,
*-- kann statt dessen die Betriebssystemzeit
*-- zum Zeitpunkt der Anzeigeformatierung ausgegeben werden.
*++ use operating system time as time stamp.
*++ .br
*++ By default
*++ .B horch
*++ uses the time stamp provided by the driver at receive time.
*++ If the driver does not support time stamps,
*++ the opearting system time can be used.
*++ Usualy this time is not the receive time, rather the display time.
*
* .TP
* -V
*-- gibt Versionsnummer auf
*++ prints the version number to
* .B stdout
*-- aus.
*
*-- DISPLAY FORMAT
*++ DISPLAY FORMAT
*-- Empfangene CAN Messages werden im Textformat angezeigt.
*-- Das allgemeine Format ist:
*++ Received CAN Messages are displayed as ASCII text strings.
*++ The basic format description is:
* .CS
[timestamp] <id-dec>/0x<id-hex> : <type> : 0{<data>}8

type:	<frametype> + <datatype>
datatype:	D|R
frametype	x|s

example:
  991330039.943806  12/0x00c : sD : 80 12 34 0d 
  991330039.944806  12/0x00c : xD : 80 12 34 0d 
  991330039.945806  4660/0x1234 : xR : (length=0)
  991330039.946806  4660/0x1234 : xD : 01 02 03 04 05 06
  991330039.947806  4660/0x1234 : xR : (length=4)
* .CE
*-- Die Message ID wird immer Dezimal und Hexadezimal dargestellt.
*-- Der führende Zeitstemple ist optional und wird durch ein
*-- interaktives Kommando aktiviert.
*-- Die Darstellung der Daten kann durch interaktive Kommandos
*-- zwischen Hexadezimal, Dezimal und ASCII-Zeichen 
*-- ausgewählt werden.
*++ The message ID is always displayed in decimal and hexa-decimal.
*++ The leading time stamp value is optional and can be activated
*++ by an interactive command.
*++ The format of the displayed data bytes 
*++ can be selected by interactive commands
*++ from decimal, hexa-decimal or ascii characters.
*
*-- INTERAKTIVE KOMMANDOS
*++ INTERACTIVE COMMANDS
.B horch
*-- kann zur Laufzeit auf seinem Eingabekanal
*-- (stdin Konsole oder von TCP/IP)
*-- Kommandos entgegennehmen,
*-- welche einige seiner Parameter ändern können.
*-- Die meisten Kommandos bestehen aus einem Kommandobuchstaben
*-- und beeinflussen die Ausgabeformatierung von CAN Nachrichten.
*-- Im Fall das stdin von der Konsole kommt,
*-- benutzt
*-- .B horch
*-- das Kommando
*-- .I stty(1)
*-- um die Konsole in die Betriebsart
*-- .B "cbreak, noecho"
*-- zu schalten.
*++ can be controlled through commands from it's stdin channel
*++ (console or TCP/IP).
*++ Most commans consist of one letter
*++ and are used to change formatting of CAN messages.
*++ In the case stdin comes from the console
*++ .B horch
*++ uses the command
*++ .I stty (1)
*++ to switch the console int the
*++ .B "raw, noecho"
*++ mode.
.TP
?
*-- On-line Hilfe, Kommandoübersicht auf stdout
*++ On-line help, command overview to stdout
.TP
a
*-- Formatierung der Datenbytes als ASCII Zeichen
*++ Formatting of data bytes as ASCII characters
.TP
b
*-- Setzen der Bit Rate on-line
*++ change bit rate on-line
* .CS
* b 125
* .CE
*-- Jeder gültige CANopen Wert ist zulässig
*++ Every valid CANopen bit rate value is allowed
.TP
c
*-- Ausgabe einer Trennlinie auf stdout
*++ print cut-mark to stdout
.TP
d
*-- Formatierung der Datenbytes als Dezimalzahlen
*++ Formatting of data bytes as decimal numbers
.TP
f
*-- Installiert ein Filter für Empfangs Nachrichten
*-- Die Filter-Format Spezifikation ist unter der Option -f beschrieben.
*++ Installes a filter for receive messages.
*++ For the format of filter specification see command option -f.
.TP
h
*-- Formatierung der Datenbytes als Hexadezimalzahlen
*++ Formattting of data bytes as hexa-decimal numbers
.TP
i
*-- Auf Linux Systemen kann ein Interpreter aufgerufen werden,
*-- welcher den aktuellen Inhalt des
*-- .B logfile
*-- interpretiert.
*++ On LINUX Systems a Interpreter progarmm can be startet
*++ which interprets and displays the content of the actual
*++ .B logfile .
.TP
l
*-- Wechselt den aktuellen Logging Zustand für lokales Aufzeichen.
*++ toggles state of lokal file logging.
*-- Logfiles werden nicht im Server Mode angelegt.
*++ Logfiles are not created in Server mode.
.TP
m acc_code acc_mask
*-- Setzt Akzeptanz und Mask Register des CAN SJA1000 Controllers.
*-- Mit diesem Kommando er\%reicht man eine Nachrichtenfilterung durch den CAN
*-- Controller.
*++ Set the content of acceptance and mask register of the SJA1000 CAN 
*++ controller chip.
*++ With the help of this command a message filter based on the CAN chip
*++ hardware is possible.
*++ (see SJA1000 documentation)
.br
*--acc_code und acc_mask
*++acc_code and acc_mask
*-- kann ein 32 bit wert in dezimaler oder hexadezimaler Schreibweise sein.
*++ can be a 32 bit value as decimal or hexadecimal number.
.TP
q
*-- Programm beenden
*++ quit program
.TP
R
*-- Resettet den CAN Controller, z.B. nach einem Error Busoff.
*++ Reset the CAN controller, e.g. after a Error Busoff.
.TP
r
*-- Rücksetzen der
*-- .B horch
*-- Statistikwerte
*++ reset the values of
*++ .B horch
*++ statistic variables.
.TP
s
*-- Ausgaben von Statistikinformationen
*++ display statistic informations
.br
*-- Es gibt hier kein allgemeingültiges Format.
*-- Die Statusinformationen sind vom verwendeten CAN Controller im 
*-- Layer-2 Treiber abhängig.
*-- Die erste Spalte gibt im Klartext den Namen des CAN-Controllers an,
*-- es folgen, als Dezimalzahlen, die Inhalte verschiedener Register.
*-- Für den am meisten verwendeten SJA1000 sieht eine Statistikzeile folgendermasssen aus:
*++ For the most often used CAN controller SJA1000 a statistic line looks like this:
.LS
:: sja1000 <act baud rate> <status register> <error_warning limit> <rx errors> <tx errors> <error code> <buslast>
.LE
.TP
t
*-- aktivieren der Anzeige von Zeitmarken.
*++ activate display of time stamps.
.TP
T
*-- deaktivieren der Anzeige von Zeitmarken.
*++ deactivate display of time stamps.
.TP
y
*-- aktivieren des Triggers
*++ start the trigger
.TP
Y
*-- deaktivieren des Trigger
*++ stop the trigger
.TP
x
*-- Übertragen von Triggereinstellungen
*++ change trigger settings
* .br
*-- Format: x idx mask RTR id [data] 
*-- idx ist ein Wert zwischen 0 und 2 und spezifiziert einen Triggerpuffer
*-- Mask ist eine Bitmaske womit don't care-Bytes in der CAN_Nachricht angegeben
*-- werden.
*-- Ist der 3 Parameter ein r so wird auf eine RTR-Nachricht hin getriggert
+-- id ist gewünschte CAN-ID
*-- data sind optionale Datenbytes der Nachricht 
*++ Format: x idx mask RTR id [data]
*++ idx is a value between 0 and 2 and specifies a trigger buffer
*++ Mask specifies which bytes are don't care bytes.
*++ Is the 2nd parameter a r, so the trigger waits for a RTR Message
*++ id is the wanted CAN-ID
*++ data are the optional data bytes of the message
.TP
w
*-- Senden einer CAN Message.
*++ send a CAN message
* .br
*-- Eine CAN Message kann gesendet werden.
*-- Nach diesem Kommando werden alle folgenden Zeichen bis zu einem NewLine
*-- als Argumente ausgewertet.
*-- Das Kommando mit Großbuchstaben \fBW\fP wird zum Senden von Nachrichten
*-- im extended Format (29 Bit) benutzt.
*-- Folgt dem Kommandobuchstaben als erstes Argument der Buchstabe \fBr\fP
*-- wird eine RTR Message versendet.
*++ A CAN message is sent.
*++ All of the letters following the command letter are interpreted
*++ as arguments.
*++ The capital command letter \fBW\fP is used to send in extended message
*++ format (using 29 bits)
*++ If the letter \fBr\fP is following the command letter as first argument,
*++ an RTR message is sent.
* .sp
* .CS
* w [r] id  0{data}8
* 
* w 222 0xaa 0x55 100   ; standard message with three data bytes
* w r 0x100 0 0 0       ; standard rtr message with data length code 3
* W 0x100 1 2           ; extended  message with two data bytes
* .CE
.TP
H
*-- Formatierung der Datenbytes als Hexadezimalzahlen
*++ Formattting of data bytes as hexa-decimal numbers
* .br
*-- Im Gegensatz zu
*-- .B h ,
*-- werden die Datensätze bei eingeschaltetem
*-- Aufzeichnen (logging) binär, als canmsg_t Struktur gespeichert.
*-- Alle anderen Formatierungen speichern die Datensätze als ASCII 
*-- Zeilen.
*++ Opposite to the
*++ .B h
*++ command letter,
*++ CAN message data are stored as binary data as canmsg_t structure
*++ if local file logging is enabled (-l).
*++ All other formats are stored as ASCII character lines.

.ig
A Filter should be installed, possibly with using the hardware
acceptance filter of the CAN controller.

Kommandos for formatting, but at least for filtering  messages
must be received by the server via socket and via stdin.

f1, 100-200, 555, 1200-
(like the page -o option of troff)

(also for the logging feature of m4d useful)
..
++ CAN ERROS
-- CAN FEHLER

-- Vom Treiber erkannte CAN Fehler werden im Klartext zur Konsole
-- geschrieben.
-- Die folgenden selbsterklärenden werden erkannt:
++ Errors recognized  by the driver are displayed at the console
++ as text messages.
++ The following messages are known:
.CS
"ERROR: OVERRUN"          CAN chip overrun
"ERROR: PASSIVE"
"ERROR: BUSOFF"
"ERROR: Buffer OVERRUN"   can4linux software buffer overrun
.CE

SEE ALSO
can4linux(7), stty(1), telnet(1)

NOROUTINES
*/

#define MAX_TRIGGER_MESSAGES 3 /* 0,1,2 */

#include <horch.h>

#if defined(EMBED) && defined(CONFIG_COLDFIRE)
#include "filter.h"
#else
#include <filter/filter.h>
#endif

#ifdef TARGET_IPC
#include <can/can.h>
#endif
#ifdef TARGET_LX_WIN_BC
# include <canopen.h>
# include <target.h>
# include <conio.h>
#endif

/* global program options, typical o_ but debug */
int debug            = FALSE;
char *log_file       = LOGFILE;
FILE *log_fp         = NULL;
char *fmt            = "%02x ";
unsigned int testCOB = TESTCOB;
int o_debugmessage   = FALSE;
int o_timestamp      = FALSE;
int save_binary      = FALSE;
int show_time        = TRUE;
int o_use_drivers_time = TRUE;
int o_server	     = FALSE;		/* TCP/IP Server */
int o_udpserver	     = FALSE;		/* UDP/IP Server */
int o_focus	     = FALSE;		/* dont switch console if IPC */
long o_period        = 1000000; /* bus load period in us, default 1 sec */
int o_show_status    = FALSE;
#ifdef TARGET_IPC
int o_bitrate	     = 125;		/* default 125kBit */
#elif defined(TARGET_LINUX)
int o_bitrate	     = 0;		/* use /proc/sys/Can/Baud */
#else
int o_bitrate	     = 125;		/* default 125kBit */
#endif
int o_btr            = FALSE;		/* if set, use o_bitrate as BTR value */
int o_portnumber     = 7235;
char device[40];			/* Device */
#ifdef TARGET_LX_WIN_BC
int board_nr	     = 0;		/* number of device */
extern int o_Device;
#endif /* TARGET_LX_WIN_BC */
#if defined(TARGET_LX_WIN_BC)
extern char o_boardname_ptr[];
#elif defined(TARGET_CPC_ECO)
/* same for unix and Windows - not used for ARM */
extern char o_boardname_ptr[];
#endif


/* other globals */
#ifdef CONFIG_SK 
unsigned long  lifecount;
#endif
unsigned long  interrupts;
unsigned long  dlines;
unsigned char 	 care_mask[MAX_TRIGGER_MESSAGES];
char 	 trigger = 0;
canmsg_t triggermessage[MAX_TRIGGER_MESSAGES];
SOCKET server_fd;           /* socket file descriptor   */
float f_busload = 0;        /* global bus load variable */
unsigned int u32_bits = 0;  /* number of received bits within a period */





/* functions */
static char	*sbuf(unsigned char *s, int n, char *fmt);
static void	usage(char *s);
static void	online_help(void);
static void	clean(void);
static int	cut_mark(void);
void 		quit(char *line);
void 	settrigger(char *);
char  	compare_msg(unsigned char, canmsg_t *, canmsg_t *);
int	getopt(int, char * const *, const char *);
void    add_bits(unsigned char, unsigned char);
static void alarmhandler (int signo); 


void termination_handler(
	int signum		/* signal to handle */
	)
{
    /* remove the file containing the process id */
#ifdef  LINUX_ARM
    if( -1 == unlink(PIDFILE)) {
	  perror("remove pid file");
    }
#endif
    clean_up();
}
/***************************************************************************
*
* main - main entrypoint
*
*/
int  main(int argc, char * argv[])
{
int id;
int c,which;
char *options;				/* getopt options string */
extern char *optarg;
extern int optind, opterr, optopt;
char *pname;
#if defined(TARGET_LINUX) 
# if defined(LINUX_ARM) || defined(CPC_LINUX)
# else /* defined(LINUX_ARM) || defined(CPC_LINUX) */
itimerval value1, ovalue;
CanStatusPar_t status;
int can_fd;
# endif /* defined(LINUX_ARM) || defined(CPC_LINUX) */
#endif /* TARGET_LINUX */

    pname = *argv;
    sprintf(device, "%s", STDDEV);

    /* common options for all versions */
    options = "CSTVab:c:dhf:l:p:s:tu"
#if defined(TARGET_LINUX)
    		"D:"		/* Driver selection */
#endif
#if defined(TARGET_LX_WIN_BC)
    		"D:U:B:"	/* Driver/DriverPort selection */
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
    		"D:"	/* Driver/DriverPort selection */
#endif
    ;

    while ((c = getopt(argc, argv, options)) != EOF) {
	switch (c) {
	    case 'C':
		o_debugmessage = TRUE;
		break;
#if defined(TARGET_LINUX)
	    case 'D':
#  ifdef TARGET_CPC_ECO
		/* Linux version of CPC driver */
		sprintf(o_boardname_ptr, "/dev/%s", optarg);
#  else /* TARGET_CPC_ECO */
		/* can4linux */
		sprintf(device, "/dev/%s", optarg);
#  endif /* TARGET_CPC_ECO */
		break;
#endif
#if defined(TARGET_LX_WIN_BC)
	    case 'D':
	    	o_Device = atoi(optarg); /* Device number */
	    	break;
	    case 'B':
		o_boardname_ptr = optarg; 	/* Boardname */
		break;
	    case 'U':
		board_nr = atoi(optarg); 	/* Board number */
		break;
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
	    case 'D':
	    	/* Win32 version of CPC driver */
	    	/* Device name found at cpcconf.ini */

	    	/*o_boardname_ptr = optarg;*/ 
		strcpy(o_boardname_ptr, optarg);
	    	break;
#endif
	    case 'S':
		o_server = TRUE;
		break;
	    case 'T':
		o_use_drivers_time = FALSE;
		break;
	    case 'u':
		o_udpserver = TRUE;
		break;
	    case 'a':
		o_btr |= 1;
		break;
	    case 'b':
		o_bitrate = (int)strtol(optarg, NULL, 0);
		o_btr |= 2;
		break;
	    case 'f':
		read_fp_string(optarg);
		break;
	    case 'l':
		log_file = optarg;
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 'c':
		testCOB =  (int)strtol(optarg, NULL, 0);
		break;
#ifndef CONFIG_SK 
	    case 'p':
		o_portnumber = (int)strtol(optarg, NULL, 0);
		break;
	    case 's':
		o_period =  1000 * atoi(optarg);
		o_show_status    = TRUE;
		break;
#endif
	    case 't':
		o_timestamp = TRUE;
		break;
	    case 'V':
		printf("\"horch\" "
#ifdef CONFIG_SK
		" SK"
#endif
		" Revision: %s, %s, %s\n",
			horch_revision, __DATE__, __TIME__);
	        exit(0);
		break;
	    case 'h':
	    default: usage(pname); exit(0);
	}
    }

    /* if -a, also -b should be used */ 
    if(o_btr & 1 && o_btr != 3) {
	fprintf(stderr, "use always -b baud when specifying -a\n\n");
	usage(pname); exit(0);
    }

#if defined(TARGET_LINUX)
    if(debug) {
	printf("using CAN device %s\n", device);
	if(o_btr & 1) {
	    printf(" use BTR0 = 0x%02x, BTR1 = 0x%02x\n",
			    o_bitrate & 0xff, o_bitrate >> 8);
	} else {
	    printf(" use bitrate %d\n", o_bitrate);
	}
    }
     /* Installing Signal handler */
    if (signal (SIGINT, termination_handler) == SIG_IGN)
	signal (SIGINT, SIG_IGN);
    if (signal (SIGHUP, termination_handler) == SIG_IGN)
	signal (SIGHUP, SIG_IGN);
    if (signal (SIGTERM, termination_handler) == SIG_IGN)
	signal (SIGTERM, SIG_IGN);
   /* SIGALRM is used to call cyclic bus load calculation */
    if (signal(SIGALRM, alarmhandler) == SIG_ERR){
        fprintf(stderr,"can't catch SIGALARM");
    }
# if defined(LINUX_ARM) || defined(CPC_LINUX)
	/* ARM-Linux version of CPC driver */
# else /* defined(LINUX_ARM) || defined(CPC_LINUX) */
    /* reading baud rate out of /proc/sys/can/Baud, if o_bitrate == 0; */
    if (o_bitrate == 0) {
        can_fd = open (device,O_RDWR);
	ioctl(can_fd, STATUS, &status);
	o_bitrate = status.baud;
	close(can_fd);
    } 	

    which = ITIMER_REAL;
    value1.it_interval.tv_sec = 0;
    value1.it_interval.tv_usec = o_period;
    value1.it_value.tv_sec = 0;
    value1.it_value.tv_usec = o_period;
    which = setitimer(which, (struct itimerval *)&value1,
    				(struct itimerval *)&ovalue);
# endif /* defined(LINUX_ARM) || defined(CPC_LINUX) */
#endif /* defined(TARGET_LINUX) */


#ifdef CONFIG_SK
    /* calculate time to life */
    /*           min          */
    lifecount = (60 * 60 * 1000000UL) / o_period; 
#endif

    /* now we are running, put our process id into /var/run */
#ifdef  LINUX_ARM
    {
    FILE *fp;
    int pid = getpid();
    	fp = fopen(PIDFILE, "w");
    	if( fp == NULL) {
	      perror("open pid file");
    	} else {
	    fprintf(fp, "%d", pid);
	    fclose(fp);
    	}
    }
#endif

    /* set trigger messages to 0x000 0x00 0x00 0x00 0x00 ... */
    settrigger(" 0 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
    settrigger(" 1 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
    settrigger(" 2 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
    /* configure terminal mode */
    set_up();

    if(o_server) {
        if(o_udpserver) {
	    udp_event_loop();
        } else {
	    server_event_loop();
	}
    } else {
	event_loop();
    }

    /* close files and devices, restore terminal settings ,... */
    termination_handler(0);
    return 0;
}



/***************************************************************************
*
* sbuf - show an byte array with format spec
*
* formats n databytes as specified in fmt.
*
* RETURNS
* .TP
* pointer to string
*/
static char *sbuf(
	unsigned char *s,	/* pointer to byte array */
	int n,			/* nuber of conversions  */
	char *fmt		/* printf() format string */
	)
{
int i;
static char string[128];
int ascii = 0;			/* flag for ascii char display */
char *ptr;

    string[0] = 0;
    ptr = &string[0];
    if( *(fmt+1) == 'c') ascii = 1;
    for(i = 0; i < n; i++) {
        if(ascii) {
	    ptr += sprintf(ptr, fmt, (*s < ' ' || *s > 0x7e) ? '.' : *s);
	    s++;
	} else {
	    ptr += sprintf(ptr, fmt, *s++);
	}
    }
    *(ptr++) = '\n';
    *ptr     = '\0';
    return(&string[0]);
}

char send_line[2056];		/* formatted message */
char debug_line[2056];		/* formatted CAN debug message */
int send_line_cnt = 0;
static char *l_ptr = &send_line[0];	/* pointer stays for multi line */

void reset_send_line(void )
{
	send_line[0] = 0;
	send_line_cnt = 0;
	l_ptr = &send_line[0];
}

/***************************************************************************
*
* add_time - display the timestamp 
*
* RETURNS
* The buffer pointer is going increment.
*/
void add_time( 
	char **pl_ptr,	/* pointer to buffer pointer */
	canmsg_t *m	/* pointer to message structur */
    )
{

    if ((show_time == TRUE) && (o_timestamp))
    {
	/* first add the timestamp to the line */
	if(o_use_drivers_time) {
#ifdef TARGET_IPC
	    *pl_ptr += sprintf(*pl_ptr, "%12lu  ", 0UL);
#else
	    *pl_ptr += sprintf(*pl_ptr, "%12lu.%06lu  ",
		m->timestamp.tv_sec,
		m->timestamp.tv_usec);
#endif
	} else {
	    *pl_ptr += show_system_time(*pl_ptr);
	}

    } /* show_time */
}

/***************************************************************************
*
* show_message - display the formatted CAN message
*
* formats the CAN message according to many flags
*
* RETURNS
* .TP
* nothing
*/
int show_message(
	canmsg_t *m		/* pointer to message struct */
	)
{
int j;
char *t_ptr;			/* temporärer Zeiger for normal can formatting*/
static char *d_ptr = &debug_line[0];	/* temporärer Zeiger for debug message*/
char **pl_ptr;		/* show to the l_ptr ord d_ptr */
char trig_c,trig_f;     /* variables for the trigger */

    *l_ptr  = '\0';
    /* detect special driver flags */
    if( m->flags & MSG_ERR_MASK ) {
	if( m->flags & MSG_OVR ) {
	    add_time(&l_ptr, m);
	    strcpy(l_ptr, "ERROR: OVERRUN\n");
	    while(*l_ptr++ != '\n');
	    /* Call skip if message at all is not useful.
	    * but continue else. Than we have two lines:
	    * 1. overrun
	    * 2. message
	    */
	    /* goto skip; */
	}
	if( m->flags & MSG_PASSIVE ) {
	    add_time(&l_ptr, m);
	    strcpy(l_ptr, "ERROR: PASSIVE\n");
	    while(*l_ptr++ != '\n');
	}
	if( m->flags & MSG_BUSOFF ) {
	    add_time(&l_ptr, m);
	    strcpy(l_ptr, "ERROR: BUSOFF\n");
	    while(*l_ptr++ != '\n');
	}
	if( m->flags & MSG_BOVR ) {
	    add_time(&l_ptr, m);
	    strcpy(l_ptr, "ERROR: Buffer OVERRUN\n");
	    while(*l_ptr++ != '\n');
	}
    } /* CAN Errors */

    /* count display lines for statistical and debugging  reasons */
    dlines++;

    /* check for debug message id */
    /* Bei der Debug Message wird Text Angezeigt, und nur bei
     * der ersten eine Timestamp, d.h. wenn kein newline in der message
     * folgt offensichtlich text,
     * und die Timestampanzeige wird unterdrückt.
     * Besser Text in einem sep Puffer sammeln, 
     * und bei der letzten Message, mit Newline, ausgeben.
     */
    if ((o_debugmessage == TRUE) && (testCOB == m->id))  {
	if ((testCOB == m->id) && (d_ptr != &debug_line[0])) {
	} else {
	    add_time( &d_ptr, m);
	}

	memcpy( d_ptr, m->data, m->length);
	d_ptr += m->length;
	*d_ptr = '\0';
	/*  test for an Carriage return */
	for (j = 0; j < m->length; j++)  {
	    if (m->data[j] == '\n')  {
		display_line(debug_line);
		d_ptr = &debug_line[0]; /* reset line */
		break;
	    }
	}
	return 0;
    } /* Debug Messages */


    if (m->id != (unsigned long)-1) {
	add_time(&l_ptr, m);

	/* No debug message, display message ID */
	show_time = TRUE; /* ?????????? */

	l_ptr += sprintf(l_ptr, "%4ld/0x%03lx : ", m->id, m->id);
	if( m->flags & MSG_EXT ) {
	    /* if message is in extended format, flag it */
	    l_ptr += sprintf(l_ptr, "x");
	} else {
	    /* if message is in standard format, flag it */
	    l_ptr += sprintf(l_ptr, "s");
	}

	if( m->flags & MSG_RTR ) {
	    l_ptr += sprintf(l_ptr, "R : ");
	    l_ptr += sprintf(l_ptr, "(length=%d)\n",(int)m->length); /* format data bytes */
	} else {
	    l_ptr += sprintf(l_ptr, "D : ");
	    t_ptr = sbuf(m->data , m->length, fmt); /* format data bytes */
	    while(*t_ptr != '\0') {
		*l_ptr++ = *t_ptr++;
	    }
	    *l_ptr = '\0';
	}
    } /* CAN Message */	

skip:
    /* Bus load messurement routines */
     add_bits(m->flags,m->length); 
    

    /* ERROR Messages will pass the Trigger */
    if ( (m->flags & MSG_ERR_MASK) == 0) {
	/* If the trigger is not used, every message is displayed */	
	if (trigger == 1) { 
	    /* here we check, if the received line matches our triggermessages */        
	    trig_f = 0; /* Trigger Flag */
	    for (trig_c = 0; (trig_c < MAX_TRIGGER_MESSAGES) && (trig_f == 0);\
	    				trig_c ++) 
	    {
	        trig_f |= compare_msg(care_mask[trig_c], m, \
	        				&triggermessage[trig_c]);
	    }

	    if (trig_f != 0 )  {
		trigger = 0;
	    } else {
	       reset_send_line();
	       return 0; 
	    }
	} /* end trigger */
    }    
    
#if 0
    if(!o_server && display_line(send_line) == -1) {
	l_ptr = &send_line[0];	/* reset format pointer */
	return -1;
    } 
    
#else /* 0 */

    
    if(!o_server) {
	/* in local mode only save to logfile */
	/* in local mode, sending to stdout, print each line */
	display_line(send_line);
	if(log_fp) {
	    /* log data to file */
	    if(save_binary) {
		/* log data to file */
		/* src, length count, fp */
		fwrite((void *)m, sizeof(canmsg_t), 1, log_fp);
	    } else {
		fprintf(log_fp, "%s", send_line);
	    }
	}
	reset_send_line();
    }

#endif /* 0 */

    if(o_server) {
	/* adjust l_ptr to end of formatted string */
	/* next message is written at the end 
	*/
	/* while(*l_ptr++ != '\n'); */
    }
    send_line_cnt = l_ptr - &send_line[0];
    return 0;
}

/*

Interpretation der Eingaben
es werden Kommandobuchstaben ausgewertet.
Die meisten Funktionen ändern das Ausgabeformat der CAN Nachricht.

Kommando 'c'
gibt eine Begrenzungslinie aus.
Bei der Ausgabe zum Socket stream kann ein Schreibfehler vorkommen.

RETURNS
.TP
OK
.TP
-1
Error while sending to socket
*/
int change_format(char c)
{
static unsigned char line[MAX_CLINE];/* command line buffer		*/
static char command = 0;	/* collect data for a complete line	*/
static int cnt = 0;		/* count input chars			*/

    if(command != '\0') {
    /* =================================================================*/
    	/* add character to command line */
    	if(c != '\n' && c != '\r') {
    	    if(cnt == MAX_CLINE) {
		command = '\0';
		cnt = 0;
		return 0;
	    }
	    line[cnt++] = c;
    	} else {
	    /*
	     * end of line, give it to a function.
	     * Line does not start with the command letter
	     * and does not end with Newline
	     */
	    line[cnt] = '\0';
	    /* first select function which has requested a line  */
	    switch(command) {
		case 'w':	/* write */
#ifdef TARGET_IPC
		    write_message(&line[0]);
#else
		    write_message(0, &line[0]);
#endif
		    break;
#ifdef TARGET_IPC
#else
		case 'W':	/* write */
		    write_message(1, &line[0]);
		    break;
#endif
		case 'f':	/* filter */
		    read_fp_string(&line[0]);
		    break;
#ifdef TARGET_IPC
#else
		case 'b':	/* bit rate */
		    set_bitrate(&line[0]);
		    break;
		case 'm':	/* acceptance mask */
		    set_acceptance(&line[0]);
		    break;
#endif
	        case 'x':	/*set Trigger parameter  */
	            settrigger(&line[0]);
	            break;
	        case 'Q':	/*set Trigger parameter  */
	            quit(&line[0]);
	            break;
		default: break;
	    }
	    command = '\0';	/* reset command -- finished */
	    cnt = 0;		/* and char counter */
    	}
    } else {
    /* =================================================================*/
        /* interpret character as command */
	switch(c) {
	/* define letters for commands which are collecting a line      */
	    case 'f':		/* filter command, collects line        */
	    case 'w':		/* write command, collects line         */
	    case 'W':
	    case 'x':          /* collects line for trigger settings    */
	    case 'Q':          /* collects line for Quit command        */
#if defined(TARGET_LINUX) || defined(__WIN32__)
	    case 'm':
	    /* set acceptance and mask register in case of SJA1000 */
	    case 'b':
	    /* set bit rate */
#endif
	    	command = c;
		break;
	/*--------------------------------------------------------------*/
	    case 'a':		/* ASCII format */
		fmt = "%c";
		break;
	    case 'c':
		/* put 'cut'-mark at display */
		return(cut_mark());
	    case 'd':		/* decimal format */
		fmt = "%03d ";
		break;
	    case 'h':		/* hex format */
		fmt = "%02x ";
		save_binary = FALSE;
		break;
#ifdef TARGET_LINUX
	    case 'i':
		system("konvert -L -x std.int -n std.nam logfile | less");
		break;
#endif
	    case 'l':
		if(log_fp) {
		    /* log file already opened */
		    fprintf(stderr, "close log file: %s\n",
						    log_file);
		    fclose(log_fp);
		    log_fp = NULL;
		} else {
		    /* must open log file 
		     * doing this with deleting the old file
		     */
		    if( (log_fp = fopen(log_file, "w")) == NULL ) {
			fprintf(stderr, "open log file error %d;",
							    errno);
			perror("");
		    }
		    fprintf(stderr, "opened log file: %s (%s)\n",
			    log_file,
			    (save_binary ? "binary" : "Ascii"));
		}
		break;
	    case 'R':
	    /* Reset the CAN contorller */
	        sprintf(line, "%d", o_bitrate);
		set_bitrate(&line[0]);
		break;
	    case 'q':
	        if(o_server) {
		    /* only for test purposes a client can finish the server */
		    /* clean_up(); */
		    return -1;
	        } else {
		    clean_up();
		}
		break;
	    case 'r':			/* reset statistik */
		interrupts = 0;
		dlines     = 0;		/* number of displayed message lines */
		break;
	    case 's':		/* show statistik */
		{
#if defined(TARGET_LINUX)
		char line[400];
		getStat(line); /* fills line !! */
		sprintf(line,"%s %.1f\n",line,f_busload);
		
#else
		char line[40];
		sprintf(line, ":: %ld Interrupts, %ld lines\n",
					    interrupts, dlines);
#endif
		send_line_cnt = strlen(line);
		display_line(line);
		send_line_cnt = 0;
		}
		break;
	    case 't':		/* activate time stamp display */
		o_timestamp = TRUE;
		break;
	    case 'T':		/* de-activate time stamp display */
		o_timestamp = FALSE;
		break;
	    case 'H':		/* Hex format and binary log */
		fmt = "%02x ";
		save_binary = TRUE;
		break;
	    case '?':
		online_help();
		break;
	    case 'y':		/* start trigger */
	    	trigger = 1;
	    	break;
	    case 'Y':		/* stop trigger */
	        trigger = 0;
	        break;
#ifdef TARGET_IPC
	    /* test for Queue overrun */
	    case ('S' - 0x40):
	        printf("---- Stopped\n");
		while(1) {
		    Sleep(2);
		    if(kbhit()) {
			if(getch() == ('Q' - 0x40)) break;
		    }
		}
	        printf("---- Continue\n");
		break;
#endif
	    default:
		break;
	}
    }
    return 0;
}


/***********************************************************************
*
* usage - print usage of the command to stderr
*
* RETURN: N/A
*
*/
static void usage(
	char *s			/* program name */
	)
{
static char *usage_text  = "\
"
#ifdef TARGET_LINUX
"\
-D    - name use CAN device name /dev/<name>, default is %s\n\
"
#endif
#ifdef TARGET_LX_WIN_BC
"\
-D    - Channel number from Level-X Board\n\
-B    - Board name of the Level-X Board\n\
-U    - Board number of the selected Board(only for registry use)\n\
"
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
"\
-D    - Channel name from EMS Board found in cpcconf.ini\n\
"
#endif
#ifdef TARGET_IPC
"\
-C    - occupy console focus\n\
"
#endif
"\
-C    - enable debug message\n\
-S    - TCP/IP Server mode\n\
-T    - dont use drivers timestamp, use OS time\n\
-a    - advanced - use \"baudrate\" as BTR0/1 value\n\
-b baudrate (Standard 125)\n\
-c<id>- use id as debug id, default %d\n\
-d    - debug On\n\
-f<spec>  - specification for receive message filter\n\
-l<file> Logfilename, logging is enabled/disabled with 'l'\n\
-p<n> - use portnumber in Servermode, default %d\n\
-s<n> - send status information every <n> ms\n\
-t    - activate time stamp at start up\n\
"
/* -u    - use UDP\n\ */
"-V    - Version\n\
\n\
for interactive commands press \'?\'\n\
";
    fprintf(stderr, "usage: %s options\n", s);
#ifdef TARGET_LINUX
    fprintf(stderr, usage_text, STDDEV, testCOB, o_portnumber);
#endif
#ifdef TARGET_LX_WIN_BC
    fprintf(stderr, usage_text, testCOB, o_portnumber);
    /* erstmal auf die Schnelle */
    fprintf(stderr,"<wait>\n");
    while( !kbhit() ){};
    scan_lx_ini("board.ini", NULL, 0, 0);
#endif
#if defined(TARGET_CPC_WIN_BC) || defined(TARGET_AC2_WIN_BC)
    fprintf(stderr, usage_text, testCOB, o_portnumber);
#endif
#ifdef TARGET_IPC
    fprintf(stderr, usage_text, testCOB, o_portnumber);
#endif
}

static void online_help(void)
{
static char *usage_text  = "\
\t\tOn-line help\n\
\t\t============\n\
? - show On-line help\n\
l - switch file logging to \"%s\" %s\n\
i - start data interpreter\n\
\n\
a - show data in ascii\n\
d - show data in dec\n\
h|H - show data hex\n\
s - statistic\n\
t/T - activate/deactivate timestamp display\n\
w - write message\n\
f<spec>  - specification for receive message filter\n\
m code mask - change acceptance\n\
b baud - change bit rate\n\
\n\
c - put 'cut'-mark at display\n\
^Q/^S start/stop; q - Quit\n\
";

    cut_mark();
    fprintf(stderr, usage_text,
	log_file, (log_fp) ? "Off" : "On"	/* -l */


    );
    cut_mark();
}


static int cut_mark(void)
{
static char line[70] =  "----------------------------------------\n";
    send_line_cnt = 41;
    if(display_line(line) == -1) {
	return -1;
    } 
    send_line_cnt = 0;
    return 0;
}

/******************************************
* quit - check for quit condition
* 
* RETURNS:
*
* nothing
********************************************/
void quit(		
        char *line	/* settrigger parameter line */
    ) /* idx dont_care RTR id data */
{
    if(strcmp(line, "uit") == 0) {
	clean_up();
    }
}
/**************************************************************************
*
* display_line - displays the formatted CAN message 
*
* changes the \n line end to \r\n
* !! calling function must provide a puffer at least two bytes
* longer than the string. !!
*/
int display_line(char *line)
{
int len;


if(*line == '\0') return 0;
/* printf(">>%s|%d|", line, */
	/* strlen(line) */
	    /* );fflush(stdout); */
    if(o_server) {

#define use_strlen
#ifdef use_strlen
	len = strlen(line);
/* printf("l: %d, ll: %d\n", len, send_line_cnt ); */
	line[len - 1] = '\r';
	line[len    ] = '\n';
	line[len + 1] = '\0';
#else
	line[send_line_cnt - 1] = '\r';
	line[send_line_cnt    ] = '\n';
	line[send_line_cnt + 1] = '\0';
/* printf("ll: %d\n", send_line_cnt ); */
#endif
	if(o_udpserver) {
	    return(sendto(server_fd, (void *)line, send_line_cnt + 1, 0,
	    		(struct sockaddr *)&fsin, sizeof(fsin) ));
	} else {
	    /* return(send(server_fd, (void *)line, send_line_cnt + 1, 0)); */
#ifdef __WIN32__	    
	    return(send(server_fd, (void *)line, len + 1, 0));
#else /* __WIN32__ */	    
	    return(send(server_fd, (void *)line, len + 1, MSG_NOSIGNAL));
#endif /* __WIN32__ */	    
	    
	}
    } else {
       fprintf(stdout, line); fflush(stdout);
       return 0;
    }
}
/* ***********************************************************
*
* The function compare_msg compares two CAN-Messages
* If message2.length == 0, only the ID and the RTR-flag are compared
*
* ret=compare_msg(msg1,msg2);
*
* return: 
* 0 if messages are unequal , not 0 if messages are equal
************************************************************/

char compare_msg(
      unsigned char     dont_care, /* select don't care bytes in the message */
      canmsg_t *eins,  /* first message */
      canmsg_t *zwei   /* second message */
      )
{

int temp2;
    /* compare id */
    if (eins->id != zwei->id) {
        return(0);
    }

    /* compare flags , only RTR */
    if ((eins->flags & MSG_RTR) != (zwei->flags & MSG_RTR)) 
    {
        return(0);
    }
    
    /* compare length */
    if (zwei->length == 0) {
        return (1);
    } 
    if (eins->length != zwei->length) {
        return (0);
    }
    
    /* compare data */ 
    for(temp2 = 0; temp2 < zwei->length; temp2++ ){
	if ( ((dont_care >> temp2) & 0x01) == 1 ) {
	    if (eins->data[temp2] != zwei->data[temp2]) {
	       return(0);
	    }
	}
    }
    
    return(1);
} /* end of function compare_msg */

#define skip_space(p) while(*(p) == ' ' || *(p) == '\t' ) (p)++
#define skip_word(p)  while(*(p) != ' ' && *(p) != '\t' ) (p)++

/******************************************
* settrigger - sets the trigger messages
* 
* RETURNS:
*
* nothing
********************************************/
void settrigger(		
        char *line	/* settrigger parameter line */
    ) /* idx dont_care RTR id data */
{
unsigned char *lptr;
unsigned char *endptr;
int len = 0;
int idx = 0;
    /* May be some check is needed if we have a valid and useful message */
    lptr = &line[0];
    skip_space(lptr);
    idx = (unsigned char) strtoul(lptr,&endptr,0);
    if (idx > (MAX_TRIGGER_MESSAGES - 1)) { 
       return;
    }
    skip_word(lptr);
    skip_space(lptr);
    
   /* don't care byte */
    care_mask[idx] = (unsigned char) strtol(lptr,&endptr,0);
    skip_word(lptr);
    skip_space(lptr);
  
   /* RTR */
   if(*lptr == 'r' || *lptr == 'R') {
	triggermessage[idx].flags=MSG_RTR;
	skip_word(lptr);
    } else {
    	triggermessage[idx].flags=0;
    }
    skip_space(lptr);
   /* ID */ 
   triggermessage[idx].id = (unsigned int)strtoul(lptr, &endptr, 0);
   while( lptr != endptr ) {
        lptr = endptr;
        triggermessage[idx].data[len] = (unsigned char)strtol(lptr, &endptr, 0);
	if(lptr != endptr) { 
	    len++;
	}    
        if(len == 8) { 
            break; /* only 8 data bytes! */
        }
    }
    triggermessage[idx].length = len;
}
/*************************************************************
*
* add_bits -  add the message's bits to the global bit counter
*
* returns: nothing 
*
**************************************************************/
void add_bits (unsigned char u8_flags,unsigned char u8_dlc) {

    if ((u8_flags & MSG_EXT) == 1) {
	 u32_bits += 65; /* 47 + 18 */ 
    } else {
	 u32_bits += 47; /* Source for 47: User Manual CANChat */
    }

    if ((u8_flags & MSG_RTR) == 0) {
	u32_bits += 8 * u8_dlc;
    }
}    

# ifdef TARGET_LINUX
/*************************************************************
* alarmhandler - calculates the bus load and set the global bus load
*		variable to the latest value
*
* this function is called by sigalrm every sample period ( o_period) 
**********************************************************/
void alarmhandler (int signo) {
    f_busload =
    (float) u32_bits * 100 / (float) (1000000 / o_period * o_bitrate * 1000);
    u32_bits = 0;
#ifdef CONFIG_SK
    if( !lifecount--) exit();
#endif
}
# endif /* TARGET_LINUX */

