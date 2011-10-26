#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# It is released under the GNU Public Licence.
#
#

if(description)
{
 script_id(14773);
 script_version ("$Revision: 1.24 $");
 
 name["english"] = "Identifies services like FTP, SMTP, NNTP...";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

This plugin performs service detection.

Description :

This plugin is a complement of find_service.nes. It attempts to 
identify services that return 3 ASCII digits codes (ie: FTP, SMTP, NNTP, ...)

Risk factor : 

None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Identifies services that return 3 ASCII digits codes";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Service detection");
 script_dependencie("find_service.nes"); # cifs445.nasl 

 # "rpcinfo.nasl", "dcetest.nasl"

# Do *not* add a port dependency  on "Services/three_digits"
# find_service2 must run after this script even if there are no
# '3 digits' services

 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/three_digits");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);	

if (thorough_tests) retry = 3;
else retry = 1;

function read_answer(socket)
{
  local_var	r, answer, i;

  repeat
  {
   for (i = 0; i <= retry; i ++)
   {
    r = recv_line(socket: socket, length: 4096);
    if (strlen(r) > 0) break;
   }
   answer += r;
  }
  until (! r || r =~ '^[0-9]{3}[^-]' || strlen(answer) > 1000000);
  return answer;
}

soc = open_sock_tcp(port);
if (! soc) exit(0);
banner = read_answer(socket: soc);

if (banner)
  replace_or_set_kb_item(name: "FindService/tcp/"+port+"/spontaneous", value: banner);
else
  debug_print('Banner is void on port ', port, ' \n');

# 500 = Unknown command
# 502 = Command not implemented

# If HELP works, it is simpler than anything else
send(socket: soc, data: 'HELP\r\n');
help = read_answer(socket: soc);
if (help)
{
  replace_or_set_kb_item(name: "FindService/tcp/"+port+"/help", value: help);
  if (! banner) banner = help; # Not normal, but better than nothing
}    

if (help !~ '^50[0-9]')
{
 if ("ARTICLE" >< help || "NEWGROUPS" >< help || "XHDR" >< help || "XOVER" >< help)
 {
  report_service(port:port, svc: 'nntp', banner: banner);
  exit(0);
 }
 # nb: this must come before FTP recognition.
 if (
  egrep(string:banner, pattern:"^220.*HylaFAX .*Version.*") ||
  egrep(string:help,   pattern:"^220.*HylaFAX .*Version.*")
 )
 {
  report_service(port: port, svc: 'hylafax', banner: banner);
  exit(0);
 }
 if ( "220 Sharp - NetScan Tool" >< banner )
 {
  report_service(port: port, svc: 'ftp', banner: banner);
  exit(0);
 }
 if ("PORT" >< help || "PASV" >< help)
 {
  report_service(port:port, svc: 'ftp', banner: banner); 
  exit(0);
 }
 # Code from find_service2.nasl
 if (help =~ '^220 .* SNPP ' || egrep(string: help, pattern: '^214 .*PAGE'))
 {
   report_service(port: port, svc: 'snpp', banner: banner);
   exit(0);
 }
 if (egrep(string: help, pattern: '^214-? ') && 'MDMFMT' >< help)
 {
  report_service(port: port, svc: 'hylafax-ftp', banner: banner);
  exit(0);
 }
}

send(socket: soc, data: 'HELO mail.nessus.org\r\n');
helo = read_answer(socket: soc);

if ( egrep(string: helo, pattern: '^250'))
{
 report_service(port:port, svc: 'smtp', banner: banner);
 exit(0);
}


send(socket: soc, data: 'DATE\r\n');
date = read_answer(socket: soc);
if (date =~ '^111[ \t]+2[0-9]{3}[01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]')
{
 report_service(port: port, svc: 'nntp', banner: banner);
 exit(0);
}

ftp_commands = make_list("CWD", "SYST", "PORT", "PASV");
ko = 0;
foreach cmd (ftp_commands)
{
  send(socket: soc, data: cmd + '\r\n');
  r = read_answer(socket: soc);
  if (egrep(string: r, pattern: '^50[0-9]')) ko ++;
  debug_print('Answer to ', cmd, ': ', r);
  if (cmd == "SYST")
  {
# We store the result of SYST just in case. Most (>99%) FTP servers answer 
# "Unix Type: L8" so this is not very informative
   v = eregmatch(string: r, pattern: '^2[0-9][0-9] +(.*)[ \t\r\n]*$');
   if (! isnull(v))
    set_kb_item(name: 'ftp/'+port+'/syst', value: v[1]);
  }
}
if (! ko)
{
  report_service(port: port, svc: 'ftp', banner: banner);
  exit(0);
}

# Code from find_service2.nasl:
# SNPP, HylaFAX FTP, HylaFAX SPP, agobot.fo, IRC bots, WinSock server,
# Note: this code must remain in find_service2.nasl until we think that
# all find_service.nes are up to date
#

if (egrep(pattern:"^220 Bot Server", string: help) ||
     raw_string(0xb0, 0x3e, 0xc3, 0x77, 0x4d, 0x5a, 0x90) >< help)
{
 report_service(port:port, svc:"agobot.fo", banner: banner);
 exit(0);
}
if ("500 P-Error" >< help && "220 Hello" >< help)	# or banner?
{
 report_service(port:port, svc:'unknown_irc_bot', banner: banner);
 exit(0);
}
if ("220 WinSock" >< help)	# or banner?
{
 report_service(port:port, svc:'winsock', banner: banner);
 exit(0);
}

# Try poppasswd
if (egrep(pattern:"^200 .* (Password service|PWD Server|poppassd)", string:banner)) {
  report_service(port:port, svc:"pop3pw", banner:banner);
  exit(0);
}
if (substr(banner, 0, 3) == '200 ')
{
 close(soc);
 soc = open_sock_tcp(port);
 if (soc)
 {
  banner = read_answer(socket: soc);
  send('USER nessus\r\n'); 
  r = read_answer(socket: soc);
  if (strlen(r) > 3 && substr(r, 0, 3) == '200 ')
  {
   send('PASS ', rand(), 'nessus\r\n'); 
   r = read_answer(socket: soc);
   if (strlen(r) > 3 && substr(r, 0, 3) == '500 ')
   {
    report_service(port:port, svc:"pop3pw", banner:banner);
    close(soc);
    exit(0);
   }
  }
  close(soc);
 }
}

# Give it to find_service2 & others
register_service(port: port, proto: 'unknown');
set_unknown_banner(port: port, banner: banner);

if (report_paranoia > 1)
{
 security_warning(port: port, data: 
'Although this service answers with 3 digit ASCII codes
like FTP, SMTP or NNTP servers, Nessus was unable to identify it.

This is highly suspicious and might be a backdoor; in this case, 
your system is compromised and a cracker can control it remotely.

** If you know what it is, consider this message as a false alert
** and please report it to the Nessus team.

Solution : disinfect or reinstall your operating system
Risk factor : High');
}
