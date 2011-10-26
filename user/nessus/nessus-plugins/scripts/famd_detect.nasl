#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# GPL
#

if(description)
{
 script_id(18186);
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "famd detection";
 script_name(english:name["english"]);
 
 desc = "
Synopsis :

A system related service which does not need to be reachable from the
network is listening on the remote port.

Description :

The File Alteration Monitor daemon is running on this port.
This service does not need to be reachable from the outside,
it is therefore recommended that reconfigure it to disable 
network access.

Solution : 

Start famd with the -L option or edit /etc/fam.conf and set the 
option 'local_only' to 'true' and restartd the famd service.

Alternatively, you may wish to filter incoming traffic to this port.

Risk factor : 

Low";

 script_description(english:desc);
 script_summary(english:"Detect the File Alteration Monitor daemon");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english:"Service detection");
 script_require_ports("Services/unknown");
 script_dependencies("find_service2.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
include('misc_func.inc');
include('network_func.inc');
include('global_settings.inc');

if ( ! thorough_tests )exit(0);

# :::FAMD
# 00: 00 00 00 10 2f 74 6d 70 2f 2e 66 61 6d 52 48 61    ..../tmp/.famRHa
# 10: 46 4c 4c 00                                        FLL.

a = get_host_ip();
# Do not use islocalhost, famd is supposed to be listening on 127.0.0.1
# only, not an external interface
local = (a =~ "^0*127\.[0-9]+\.[0-9]+\.[0-9]+$");
lan = local || is_private_addr(addr: a);

port = get_unknown_svc();
if (! port) exit(0);	# famd runs on any free privileged port??

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0\0\0\x1aN0 500 500 sockmeister\00\x0a\0');
b = recv(socket: s, length: 512);
close(s);
if (isnull(b) || substr(b, 0, 2) != '\0\0\0') exit(0);
# First test triggers against HP Openview or Tibco
l = strlen(b);
if (l < 5 || b[l-1] != '\0' || ord(b[3]) != l - 4 || ord(b[4]) != '/' ) exit(0);

register_service(port: port, ipproto: 'tcp', proto: 'famd');

r = 'The File Alteration Monitor daemon is running on this port.\n';

if (local) security_note(port: port, data: r + '.\n\nRisk factor : None\n');
else
{
 r += ' and does not need\nto be reachable from the outside.\n';

 if (! lan)
  r += 'Exposing it on Internet is definitely not a good idea.\n';
 r += '\nSolution : to restrict it to the loopback interface, 
run it with -L or set "local_only = false" in /etc/fam.conf\n\nRisk factor : Low';
 security_warning(port: port, data: r);
}
