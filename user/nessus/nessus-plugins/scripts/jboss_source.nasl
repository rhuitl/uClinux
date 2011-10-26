#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#
# 

if(description)
{
 script_id(11690);
 script_bugtraq_id(7764);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "JBoss source disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is vulnerable to information disclosure attacks.

Description :

It is possible to make the remote web server disclose the source code of
its JSP pages by appending a NULL character to the name of the JSP files
requested (eg, 'foo.jsp%00').  An attacker may use this flaw to get the
source code of scripts on the remote host and possibly obtain passwords
and other sensitive information.

See also :

http://www.securityfocus.com/archive/1/323430

Solution : 

None at this time

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read the source of a jsp page";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function check(file)
{
 req = http_get(item:file, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<%" >< res) return 1;
 return 0;
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/web-console/ServerInfo.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file) == 0)
   {
   file = str_replace(string:file, find:".jsp", replace:".jsp%00");
   if(check(file:file)) { security_hole(port); exit(0); }
  }
  n ++;
  if(n > 20)break;
  }
 }
}
