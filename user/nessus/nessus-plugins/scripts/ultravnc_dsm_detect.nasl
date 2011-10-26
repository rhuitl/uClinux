#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# It is released under the GNU Public Licence

if(description)
{
 script_id(19289);
 script_version ("$Revision: 1.4 $");
 
 script_name(english: "UltraVNC w/ DSM plugin detection");
 
 desc = "
Synopsis :

A remote control service is running on this port.

Description :

UltraVNC seems to be running on the remote port.

Upon connection, the remote service on this port always sends
the same 12 pseudo-random bytes.

It is probably UltraVNC with the DSM encryption plugin.
This plugin tunnels the RFB protocol into a RC4 encrypted 
stream.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";


 script_description(english:desc);
 
 script_summary(english: "Detect 12 pseudo-random bytes in banner (UltraVNC w/ DSM)");
 
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl", "vnc.nasl");
 script_require_ports("Services/unknown", 5900);
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");
include("dump.inc");

if ( thorough_tests )
{
 port = get_unknown_svc(5900);
 if (! port) exit(0);
}
else port = 5900;

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

b = get_kb_item('FindService/tcp/'+port+'/spontaneous');
if (! COMMAND_LINE && strlen(b) != 12) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
r1 = recv(socket: s, length: 512);
send(socket: s, data: '012345678901');
r = recv(socket: s, length: 512);
close(s);

if (debug_level > 0)
{
 t = strcat("Data received on ", get_host_ip(), ':', port);
 dump(ddata: r1, dtitle: t);
 dump(ddata: r, dtitle: t);
}

if (strlen(r1) != 12) exit(0);

# Should have been picked by vnc.nasl or find_service*
if (ereg(string: r1, pattern: '^RFB +[0-9]+\\.[0-9]+\n$', icase: 0, multiline: 1))
{
 log_print('Clear text VNC banner on port ', port, '\n');
 register_service(port: port, proto: 'vnc');
 exit(0);
}
# Let this test here: clear text VNC answers to my silly "request"
if (strlen(r) > 0) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
r2 = recv(socket: s, length: 512);
if (r2 != r1) exit(0);
send(socket: s, data: r2);
r = recv(socket: s, length: 512);
close(s);
if (debug_level > 0)
{
 dump(ddata: r2, dtitle: t);
 dump(ddata: r, dtitle: t);
}

if (strlen(r) == 0) exit(0);

# aka statistical test, because I'm paranoid

total = 0;
all_ascii = TRUE;
for (i = 0; i < 12; i ++)
{
 z = ord(r[i]);
 if (z < 9 || z > 126) all_ascii = 0;
#if (z == 0 || z > 127) all_ascii = 0;
 for (j = 1; j < 256; j *= 2)
  if (z & j) total ++;
}

debug_print('port=', port, '- all_ascii=', all_ascii, ' - total=', total, '\n');

if (all_ascii)
{
 debug_print('Banner is in ASCII characters\n');
 if (report_paranoia < 1) exit(0);
}

if (total >= 24 && total <= 72)
{
 security_note(port: port);
 register_service(port: port, proto: 'ultravnc-dsm');
}
# Else statistical test failed
