# This script was written by Michel Arboi <mikhail@nessus.org>
# It is released under the GNU Public Licence.

if(description)
{
 script_id(17975);
 script_version ("$Revision: 1.57 $");
 
 name["english"] = "Identify unknown services with GET";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

This plugin performs service detection.

Description :

This plugin is a complement of find_service.nes. It sends a GET
request to the remaining unknown services and tries to identify 
them.

Risk factor : 

None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sends 'GET' to unknown services and look at the answer";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("find_service.nes", "cifs445.nasl");
# Do *not* add a port dependency  on "Services/unknown"
# Some scripts must run after this script even if there are no
# unknown services
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");

port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

# If the service displays a banner on connection, find_service.c does not
# send a GET request. However, if a GET request was sent and the service
# remains silent, the get_http KB entry is void

r0 = get_kb_item('FindService/tcp/'+port+'/spontaneous');	# Banner?
get_sent = 1;
if (strlen(r0) > 0)	# We have a spontaneous banner
{
 get_sent = 0;	# spontaneous banner => no GET request was sent by find_service

###################################################
######## Updates for "spontaneous" banners ########
###################################################

if (r0 =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+')
{
 debug_print('Fake IDENTD found on port ', port, '\n');
 register_service(port: port, proto: 'fake-identd');
 set_kb_item(name: 'fake_identd/'+port, value: TRUE);
 exit(0);
}

if (match(string: r0, pattern: 'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *'))
{
 report_service(port: port, svc: 'smsc');
 exit(0);
}

if (r0 == '\x00\x00\x00\x0D\xD5\xF2Who are you?\x0A\x00')
{
 # Port doc1lm (3161/tcp)
 # PatrolAgent (BMC Patrol)
 report_service(port: port, svc: 'patrol-agent');
 exit(0);
}


if ( '\x00\x00\x00\x0bSynergy' >< r0 )
{
 # Synergy Server
 report_service(port: port, svc: 'synergys');
 exit(0);
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a . 

if (ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:r0) ||
# Daytime in German
ereg(pattern:"^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +([0-2][0-9]|3[01])\.(0[1-9]|1[0-2])\.(19|20)[0-9][0-9]$", string: r0)
)
{
 report_service(port: port, svc: 'daytime');
 exit(0);
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if (r0 =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}

if (match(string: r0, pattern: '220 *FTP Server ready\r\n'))
{
 report_service(port: port, svc: 'ftp');
 exit(0);
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if (match(string: r0, pattern: '"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*'))
{
 register_service(port: port, proto: 'sieve');
 security_note(port: port, data: 'Sieve mail filter daemon seems to be running on this port');
 exit(0);
}

# I'm not sure it should go here or in find_service2...
if (match(string: r0, pattern: '220 Axis Developer Board*'))
{
 report_service(port: port, svc: 'axis-developer-board');
 exit(0);
}

if (match(string: r0, pattern: '  \x5f\x5f\x5f           *Copyright (C) 1999, 2000, 2001, 2002 Eggheads Development Team'))
{
 report_service(port: port, svc: 'eggdrop');
 exit(0);
}

# Music Player Daemon from www.musicpd.org
if (ereg(string: r0, pattern: '^OK MPD [0-9.]+\n'))
{
 report_service(port: port, svc: 'mpd');
 exit(0);
}

# Eudora Internet Mail Server ACAP server.
if ("* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< r0)
{
 report_service(port: port, svc: 'acap');
 exit(0);
}

# Sophos Remote Messaging / Management Server
if ("IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r0)
{
 report_service(port: port, svc: 'sophos_rms');
 exit(0);
}

# Ipswitch Collaboration Suite WorkgroupShare Server.
if (egrep(pattern:"^OK WorkgroupShare .+ server ready", string:r0))
{
  report_service(port:port, svc:"WorkgroupShare");
  exit(0);
}

if (r0 =~ '^\\* *BYE ')
{
  report_service(port: port, svc: 'imap', banner: r0);
  security_note(port: port, data: 'The IMAP server rejects connection from our host. We cannot test it');
  exit(0);
}

# General case should be handled by find_service_3digits
if (match(string: r0, pattern: '200 CommuniGatePro PWD Server * ready*'))
{
 report_service(port: port, svc: 'pop3pw');
 exit(0);
}


# Should be handled by find_service already
if (r0 =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}


if (r0 =~ '^welcome to the pioneers-meta-server version [0-9]\\.')
{
 report_service(port: port, svc: 'pioneers-meta-server');
 security_note(port:port, data:"A meta server for the game Pioneers is running on this port.");
 exit(0);
}

# MA 2008-08-30: AIX lpd - Yes! This is a "spontaneous" banner
if (r0 =~ "^[0-9]+-[0-9]+ ill-formed FROM address.$")
{
 report_service(port: port, svc: 'lpd');
 security_note(port: port, 'An LPD server (probably AIX) is running on this
 port');
 exit(0);
}

# German W2K3 qotd
if (ereg(string: r0, multiline: 1, pattern: '..........\n\\((Federico Fellini|Juliette Gréco|Berthold Brecht|Volksweisheit|Mark Twain|Bertrand Russell|Helen Markel|Fritz Muliar|Anatole France|Albert Einstein|Oscar Wilde|August von Kotzebue|Tschechisches Sprichwort|Schweizer Sprichwort|Mark Twain)\\)$'))
{
 register_service(port:port, proto: "qotd");
 security_note(port: port, data: "qotd seems to be running on this port");
 exit(0);
}

# From Jim Heifetz
# Runs on port 10007 of z/OS Communication Server
# It always returns an eight digit number.

if (r0 =~ '^0000[0-9][0-9][0-9][0-9]$')
{
 register_service(port:port, proto: "mvs-capacity");	# should we call it bpxoinit?
 security_note(port: port, data: "BPXOINIT (MVS capacity) seems to be running on this port");
 exit(0);
}

if ("220 Ipswitch Notification Server" >< r0)
{
  register_service(port:port, proto:'ipswitch_ns');
  security_note(
    port:port, 
    data:"An Ipswitch Notification Server is running on this port."
  );
 exit(0);
}

#
# Keep qotd at the end of the list, as it may generate false detection
#

if (r0 =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$')
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd seems to be running on this port");
  exit(0);
}

}	# else: no spontaneous banner

###################################################
######## Updates for answers to GET / ...  ########
###################################################

k = 'FindService/tcp/'+port+'/get_http';
r = get_kb_item(k+'Hex');
if (strlen(r) > 0) r = hex2raw(s: r);
else r = get_kb_item(k);

r_len = strlen(r);
if (r_len == 0)
{
 if (get_sent			# Service did not anwer to GET
     && ! thorough_tests)	# We try again in "thorough tests"
  exit(0);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
 r = recv(socket:soc, length:4096);
 close(soc);
 r_len = strlen(r);
 if (r_len == 0)
 {
   debug_print('Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n');
   exit(0);
 }
 set_kb_item(name: k, value: r);
 if ('\0' >< r) set_kb_item(name: k + 'Hex', value: hexstr(r));
}

# aka HTTP/0.9
if (r =~ '^[ \t\r\n]*<HTML>.*</HTML>' ||
# In case of truncated answer
    r=~ '^[ \t\r\n]*<HTML>[ \t\r\n]*<HEAD>.*</HEAD>[ \t\r\n]*<BODY( +[^>]+)?>')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0);
}

if (r == '[TS]\r\n')
{
 report_service(port: port, svc: 'teamspeak-tcpquery', banner: r);
 exit(0);
}

# Veritas Backup Exec Remote Agent (6103/tcp)
if (r == '\xF6\xFF\xFF\xFF\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' )
{
  register_service(port: port, proto: "backup_exec");
  security_note(port: port, data: "Veritas Backup Exec Remote Agent is running on this port");
  exit(0);
}

if (r == 'gethostbyaddr: Error 0\n')
{
 register_service(port:port, proto:"veritas-netbackup-client");
 security_note(port:port, data:"Veritas NetBackup Client Service is running on this port");
 exit(0);
}

if ("GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r)
{
 report_service(port: port, svc: 'auth', banner: r);
 exit(0);
}

if ('Host' >< r && 'is not allowed to connect to this MySQL server' >< r)
{
 register_service(port: port, proto: 'mysql');	# or wrapped?
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but it
rejects connection from the Nessus scanner.");
  exit(0);
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if ('Host' >< r && ' is blocked ' >< r && 'mysqladmin flush-hosts' >< r)
{
 register_service(port: port, proto: 'mysql');
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but the 
Nessus scanner IP has been blacklisted.
Run 'mysqladmin flush-hosts' if you want complete tests.");
  exit(0);
}


if ( "Asterisk Call Manager" >< r )
{
 register_service(port: port, proto: 'asterisk');
 security_note(port: port, data: "An Asterisk Call Manager server is running on this port.");
  exit(0);
}

# Taken from find_service2 (obsolete, as the string contains a \0)
if (r_len == 3 && (r[2] == '\x10'||	# same test as find_service
                   r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 .. 
# 00: F8 2D 0B 00 00 16 .-.... 
if ((r_len == 5 || r_len == 6) && r[3] == '\0' && 
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0')
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

if (r == '\x01Permission denied' || 
   ( "lpd " >< r && "Print-services" >< r )  )
{
  report_service(port: port, svc: 'lpd');
  security_note(port: port, data: 'An LPD server is running on this port');
  exit(0);
}

#### Double check: all this should be handled by find_service.nes ####

# Spamd (port 783) - permissive Regex, just in case
if (r =~ '^SPAMD/[0-9.]+ [0-9]+ Bad header line:')
{
 register_service(port:port, proto:"spamd");
 security_note(port:port, data:"A SpamAssassin daemon is running on this port");
 exit(0);
}

if (r == 'GET / HTTP/1.0\r\n\r\n')
{
 report_service(port: port, svc: 'echo', banner: r);
 exit(0);
}

# Should we excluded port=5000...? (see find_service.c)
if (r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0); 
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if (r =~ '^[0-9][0-9][0-9]-?[ \t]')
{
 debug_print('"3 digits" found on port ', port, ' in response to GET\n');
 register_service(port: port, proto: 'three_digits');
 exit(0); 
}

if (r =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}

if (match(string: r, pattern: "Language received from client:*Setlocale:*"))
{
  report_service(port: port, svc: "websm");
  exit(0);
}

#### Some spontaneous banners are coming slowly, so they are wronly 
#### registered as answers to GET
 
if (r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}
