#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11004);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-1999-0508");
 name["english"] = "WhatsUp Gold Default Admin Account";
 script_name(english:name["english"]);

 desc["english"] = "
 
This WhatsUp Gold server still has the default password for
the admin user account. An attacker can use this account to
probe other systems on the network and obtain sensitive 
information about the monitored systems.

Solution: Login to this system and either disable the admin
account or assign it a difficult to guess password.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "WhatsUp Gold Default Admin Account";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if (soc)
  {
    req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4K\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if ("Whatsup Gold" >< buf && "Unauthorized User" >!< buf)
    {
     security_hole(port:port);
    }
  }
 }
