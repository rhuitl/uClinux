#
# This script was written by Michel Arboi <arboi@alussinan.org>
#

if(description)
{
 script_id(19288);
 script_version ("$Revision: 1.5 $");
 script_name(english: "VNC security types");
 
 desc = "
This script checks the remote VNC protocol version
and the available 'security types'.
";

 script_description(english:desc);
 
 script_summary(english: "Identifies the RFB protocol version (VNC) & security types");
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Misc.");
 script_dependencie("vnc.nasl");
 script_require_ports("Services/vnc", 5900);
 exit(0);
}

#

include('misc_func.inc');
include('global_settings.inc');
include('network_func.inc');


port = get_kb_item("Services/vnc");
if (! port) port = 5900;	# or 5901, 5902...?

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if(! s) exit(0);

r = recv(socket: s, length: 512, min: 12);
if (strlen(r) < 12) exit(0);

v = eregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v)) exit(0);

major = int(v[1]);
minor = int(v[2]);

debug_print('RFB protocol version = ', major, '.', minor, '\n');

if (major < 3)
{
 debug_print('Unsupported RFB major protocol version ', major, '.', minor, '\n');
 exit(0);
}

# Send back the same protocol
send(socket: s, data: r);

# Security types names
rfb_sec = make_array(	0, "Invalid", 1, "None", 2, "VNC authentication",
 5, "RA2", 6, "RA2ne", 16, "Tight", 17, "Ultra", 18, "TLS");

if (major == 3 && minor >= 3 && minor < 7)
{
 r = recv(socket: s, min: 4, length: 4);
 if (strlen(r) != 4)
 {
  debug_print('Could not read security type\n');
  exit(0);
 }
 st = ntohl(n: r);
 report = strcat('The remote VNC server chose security type #', st);
 if (rfb_sec[st])
  report = strcat(report, ' (', rfb_sec[st], ')');

 if (st <= 1)
  if (is_private_addr())
   security_warning(port: port, data: report + "
Allowing no authentication is a security risk, even on a private network.

Solution :

Enable at least VNC authentication");
  else
   security_hole(port: port, data: report + "
Any user can connect to it without authentication, and thus take
control of this machine.

Solution : 

Enforce at least VNC authentication");
 else
  security_note(port: port, data: report);

}
else if (major > 3 || minor >= 7)
{
 r = recv(socket: s, min: 1, length: 1);
 if (strlen(r) < 1)
 {
  debug_print('Could not read number of security types\n');
  exit(0);
 }
 n = ord(r);
 if (n == 0)	# rejected connection
 {
  reason = '';
  r = recv(socket: s, min: 4, length: 4);
  if (strlen(r) == 4)
  {
    l = htonl(n: r);
    reason = recv(socket: s, length: l);
  }
  report = 'The remote VNC server rejected the connection.\n';
  if (strlen(reason) > 0)
   security_note(port: port, data: strcat(report, 'Reason: ', reason));
  else
   security_note(port: port, data: strcat(report, 'Nessus could not read the reason why.'));
 }
 else
 {
  report = 'The remote VNC server supports those security types:\n';
  min = 9999;
  for (i = 0; i < n; i ++)
  {
   r = recv(socket: s, min: 1, length: 1);
   if (strlen(r) < 1)
   {
    debug_print('Could not read security type #', i, '/', n);
    break;
   }
   st = ord(r);
   if (rfb_sec[st])
    report = strcat(report, '+ ', st, ' (', rfb_sec[st], ')\n'); 
   else
    report = strcat(report, '+ ', st, '\n');
   if (st < min) min = st;
  }

 if (min <= 1)
  if (is_private_addr())
   security_warning(port: port, data: report + "
Allowing no authentication is a security risk, even on a private network.

Solution :

Enable at least VNC authentication");
  else
   security_hole(port: port, data: report + "
Any user can connect to it without authentication, and thus take
control of this machine.

Solution : 

Enforce at least VNC authentication");
 else
  security_note(port: port, data: report);

 }
}
else
{
 debug_print('Unsupported RFB minor protocol version ', major, '.', minor, '\n');
 exit(0);
}

if (service_is_unknown(port: port))
  register_service(port: port, proto: 'vnc');
