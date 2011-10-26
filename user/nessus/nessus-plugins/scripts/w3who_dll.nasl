# 
# (C) Nicolas Gregoire <ngregoire@exaprobe.com>
#
#

if(description)
{
 script_id(15910);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-1133");
 script_cve_id("CVE-2004-1134");
 script_bugtraq_id(11820);

 name["english"] = "w3who.dll overflow and XSS";

  
 script_name(english:name["english"]);
 
 desc["english"] = "
The Windows 2000 Resource Kit ships with a DLL that displays
the browser client context. It lists security identifiers,
privileges and $ENV variables. 

Nessus has determined that this file is installed on the remote host.

The w3who.dll ISAPI may allow an attacker to execute arbitrary commands 
on this host, through a buffer overflow, or to mount XSS attacks.

See also : http://www.exaprobe.com/labs/advisories/esa-2004-1206.html 
Solution : Delete this file
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of w3who.dll";


 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Nicolas Gregoire <ngregoire@exaprobe.com>");

 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

req  = http_get(item:"/scripts/w3who.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);
if("Access Token" >< res)
{
 if(safe_checks()) {
   security_warning(port);
   exit(0);
   }
  
  
  req = string("GET /scripts/w3who.dll?", crap(600), " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "User-Agent: Nessus\r\n");

 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 # The page content is subject to localization
 # Matching on headers and title
 if("HTTP/1.1 500 Server Error" >< r &&
    "<html><head><title>Error</title>" >< r) security_hole(port);
}
exit(0);
