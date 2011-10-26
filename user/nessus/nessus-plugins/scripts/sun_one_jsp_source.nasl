#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "SPI Labs" <spilabs@spidynamics.com>
# To: <bugtraq@securityfocus.com>
# Subject: Multiple Vulnerabilities in Sun-One Application Server
# Date: Tue, 27 May 2003 18:48:04 -0400  

if(description)
{
 script_id(11658);
 script_bugtraq_id(7709);
 script_cve_id("CVE-2003-0411");
 script_version("$Revision: 1.6 $");
 
 name["english"] = "SunONE Application Server source disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote web server disclose the source
code of its JSP pages by requesting the pages with a different
case (ie: filename.JSP instead of filename.jsp).

An attacker may use this flaw to get the source code of your CGIs
and possibly obtain passwords and other relevant information about
this host.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read the source of a jsp page";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(file)
{
 req = http_get(item:file, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<%" >< res) return 1;
 return 0;
}

port = get_http_port(default:80);

if(get_port_state(port))
{
 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/index.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file) == 0)
   {
   file = str_replace(string:file, find:".jsp", replace:".JSP");
   if(check(file:file)) { security_hole(port); exit(0); }
  }
  n ++;
  if(n > 20)exit(0);
 }
}
