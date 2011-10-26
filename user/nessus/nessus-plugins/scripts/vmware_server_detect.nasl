#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#


if(description)
{
  script_id(20301);
  script_version ("$Revision: 1.2 $");
 
  script_name(english:"VMware ESX/GSX Server detection");
 
  desc["english"] = "
Synopsis :

The remote host appears to be running VMware ESX or GSX Server.

Description :

According to its banner, the remote host appears to be running a VMWare server authentication daemon, which likely indicates the remote host is running VMware ESX or GSX Server.

See also : 

http://www.vmware.com/

Risk factor : 

None";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect VMware Server Authentication Daemon";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes");
  script_require_ports("Services/unknown", 902);

  exit(0);
}

#the code
include("misc_func.inc");

if (thorough_tests) {
  port = get_unknown_svc(902);
  if ( ! port ) exit(0);
}
else port = 902;
if (!get_tcp_port_state(port)) exit(0);


banner = get_unknown_banner(port: port, dontfetch:0);
if (banner) {
  #220 VMware Authentication Daemon Version 1.00
  #220 VMware Authentication Daemon Version 1.10: SSL Required
  if ("VMware Authentication Daemon Version" >< banner) {
    register_service(port:port, ipproto:"tcp", proto:"vmware_auth_daemon");

    security_note(port);
  }
}
