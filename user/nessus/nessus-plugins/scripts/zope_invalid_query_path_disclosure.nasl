#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11769);
 script_bugtraq_id(7999, 8000, 8001);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Zope Invalid Query Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that is prone to
information disclosure. 

Description :

The remote Zope web server may be forced into disclosing its physical
path when it receives bad arguments for several example CGIs included
in the installation. 

See also :

http://exploitlabs.com/files/advisories/EXPL-A-2003-009-zope.txt

Solution : 

Delete the directory '/Examples'.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for Zope Examples directory";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) port = 8080;
if(!get_port_state(port)) exit(0);


req = http_get(port:port, item:"/Examples/ShoppingCart/addItems?orders.id%3Arecords=510-007&orders.quantity%3Arecords=&orders.id%3Arecords=510-122&orders.quantity%3Arecords=0&orders.id%3Arecords=510-115&orders.quantity%3Arecords=0");
a = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (a == NULL) exit(0);

if("invalid literal for int()" >< a && "Publish.py"  >< a)
{
  security_note(port);
  }
