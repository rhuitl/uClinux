# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL...
#

if(description)
{
 script_id(18528);
 script_version ("$Revision: 1.8 $");
 script_name(english:"SMTP server accepts us");
 script_description(english:
"This script does not perform any security test.
It verifies that Nessus that connect to the remote SMTP
server and that it can send a HELO request.");
		 
 script_summary(english: "Checks that the SMTP server accepts our HELO");
 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');
include('smtp_func.inc');

port = get_kb_item("Services/smtp");
if (! port) port = 25;
if (! get_port_state(port)) exit(0);

# Some broken servers return _two_ code lines for one query!
# Maybe this function should be put in smtp_func.inc?
function smtp_recv(socket, retry)
{
 local_var r, r2, i, l;
 for (i = 0; i < 6; i ++)
 {
  r = recv(socket: socket, length: 4096);
  l = strlen(r);
  if (l == 0 && retry -- <= 0) return r2;
  r2 += r;
  if (l >= 2 && substr(r, l-2) == '\r\n') return r2;
 }
 return r2;
}

s = open_sock_tcp(port);

if (! s)
{
 debug_print('Cannot open connection to port ', port, '\n');
 set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
 if (port == 25)
  set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 exit(0);
}

r = smtp_recv(socket: s, retry: 3);
if (! r)
{
 debug_print('No SMTP welcome banner on port ', port, '\n');
 close(s);
 set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
 if (port == 25)
  set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 exit(0);
}

if (r =~ '^4[0-9][0-9][ -]')
{
 debug_print('SMTP on port ', port, ' is temporarily closed: ', r);
 security_note(port: port, data: strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code.
This means that it is temporarily unavailable because it is
overloaded or any other reason.

** Nessus tests will be incomplete. You should fix your MTA and
** rerun Nessus, or disable this server if you don't use it.
"));
 close(s);
 set_kb_item(name:'smtp/'+port+'/temp_denied', value: TRUE);
 exit(0);
}

if (r =~ '^5[0-9][0-9][ -]')
{
 debug_print('SMTP on port ', port, ' is permanently closed: ', r);
 security_note(port: port, data: strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code.
This means that it is permanently unavailable because the Nessus
server IP is not authorized, blacklisted or any other reason.

** Nessus tests will be incomplete. You may try to scan your MTA
** from an authorized IP or disable this server if you don't use it.
"));
 set_kb_item(name: 'smtp/'+port+'/denied', value: TRUE);
 close(s);
 exit(0);
}

heloname = 'example.com';
send(socket: s, data: 'HELO '+heloname+'\r\n');
r = smtp_recv(socket: s, retry: 3);
if (r =~ '^[45][0-9][0-9][ -]')
{
 debug_print('SMTP server on port ', port, ' answers to HELO(', heloname, '): ', r);
 heloname = this_host_name();
 if (! heloname) heloname = this_host();
 send(socket: s, data: 'HELO '+heloname+'\r\n');
 r = smtp_recv(socket: s, retry: 3);
 if (strlen(r) == 0)	# Broken connection ?
 {
  close(s);
  sleep(1);	# Try to avoid auto-blacklist
  s = open_sock_tcp(port);
  if (s)
  {
   send(socket: s, data: 'HELO '+heloname+'\r\n');
   r = smtp_recv(socket: s, retry: 3);
  }
 } 
 debug_print('SMTP server on port ', port, ' answers to HELO(', heloname, '): ', r);
}

debug_print(level: 2, 'SMTP server on port ', port, ' answers to HELO: ', r);

send(socket: s, data: 'QUIT\r\n');
close(s);

if (r !~ '^2[0-9][0-9][ -]')
{
 if (strlen(r) >= 3)
  report = strcat(
"The SMTP server on this port answered with a ", substr(r, 0, 2), " code
to HELO requests.");
 else
  report = "The SMTP server on this port rejects our HELO requests.";
 report += "
This means that it is unavailable because the Nessus server IP is not 
authorized or blacklisted, or that the hostname is not consistent
with the IP.

** Nessus tests will be incomplete. You may try to scan your MTA
** from an authorized IP or fix the nessus hostname and rescan this server.
";
 
 security_note(port: port, data: report);
 set_kb_item(name: 'smtp/'+port+'/denied', value: TRUE);
}
else
{
 if ( heloname ) set_kb_item(name: 'smtp/'+port+'/helo', value: heloname);
}
