#
# copyright 2001 by Holm Diening / SLITE IT-Security (holm.diening@slite.de)
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10730);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Raptor FW version 6.5 detection";

 script_name(english:name["english"]);

 desc["english"] = "
 By sending an invalid HTTP request to an
 webserver behind Raptor firewall, the http
 proxy itself will respond.

 The server banner of Raptor FW version 6.5
 is always 'Simple, Secure Web Server 1.1'

 You should avoid giving an attacker such
 information.

 Solution: patch httpd / httpd.exe by hand

 Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Checks if the remote host is protected by Raptor FW 6.5";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2000 Holm Diening");
 family["english"] = "Firewalls";

 script_family(english:family["english"]);

 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
port = get_http_port(default:80);


if(get_port_state(port))
{
 socwww = open_sock_tcp(port);

 if (socwww)
  {
   teststring = string("some invalid request\r\n\r\n");
   testpattern = string("Simple, Secure Web Server 1.");
   send(socket:socwww, data:teststring);
   recv = http_recv(socket:socwww);
   if (testpattern >< recv)
   {
    report = string("The remote WWW host is very likely behind Raptor FW Version 6.5\n", "You should patch the httpd proxy to return bogus version and stop\n", "the information leak\n");
    security_note(port:port, data:report);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
   }
  close(socwww);
  }
 }
