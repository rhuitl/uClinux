#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running gdbserver, a program which can be used to run
the GDB debugger on a different machine than the one which is running the
program being debugged.

Since gdbserver offers no authentication whatsoever, an attacker may connect
to this port, change the value of the registers and the memory of the process
being debugged, and therefore be able to execute arbitrary code on the remote
host with the privileges of the process being debugged.


See also :

http://sources.redhat.com/gdb/current/onlinedocs/gdb_18.html#SEC162

Solution :

Filter incoming traffic to this port or disable this service

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(21245);
  script_version("$Revision: 1.5 $");

  script_name(english:"GDB Server Detection");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_summary(english:"Detects the remote gdb server");
  script_dependencies("find_service2.nasl", "dcetest.nasl");
  script_require_ports("Services/unknown");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if ( ! thorough_tests ) exit(0);

port = get_unknown_svc();
if ( ! port ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:'+$Hc-1#09');
r = recv(socket:soc, length:9);
close(soc);
if ( strlen(r) < 4 ) exit(0);
if ( substr(r, 0, 3) == '+$OK' ) security_hole(port);
