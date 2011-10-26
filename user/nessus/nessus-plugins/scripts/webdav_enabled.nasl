#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11424);
  script_version ("$Revision: 1.8 $");
  name["english"] = "WebDAV enabled";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote server is running with WebDAV enabled. 

Description :

WebDAV is an industry standard extension to the HTTP specification.
It adds a capability for authorized users to remotely add and manage
the content of a web server.

If you do not use this extension, you should disable it.

Solution :

http://support.microsoft.com/default.aspx?kbid=241520

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


 script_description(english:desc["english"]);

 summary["english"] = "Checks the presence of WebDAV";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");

 family["english"] = "General";

 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  req = string("OPTIONS * HTTP/1.0\r\n\r\n") ;
  send(socket:soc, data:req);
  r = http_recv_headers2(socket:soc);
  close(soc);
  if(egrep(pattern:"^DAV: ", string:r))
   {
    security_note(port);
   }
  }
}
