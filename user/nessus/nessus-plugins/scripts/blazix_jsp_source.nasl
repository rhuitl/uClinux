#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17151);
 script_bugtraq_id(5566, 5567);
 script_cve_id("CVE-2002-1451");
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Blazix Web Server JSP source disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote web server disclose the source
code of its JSP pages by requesting the pages while appending a plus
sign or a backslash to its name (ie: filename.jsp+ instead of filename.jsp).

An attacker may use this flaw to get the source code of your CGIs
and possibly obtain passwords and other relevant information about
this host.

Solution : Upgrade to Blazix 1.2.1 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read the source of a jsp page";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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
banner = get_http_banner(port:port);
if ("Server: Blazix Java Server" >!< banner ) exit(0);

if(get_port_state(port))
{
 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/index.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file) == 0)
   {
   file = str_replace(string:file, find:".jsp", replace:".jsp+");
   if(check(file:file)) { security_hole(port); exit(0); }
  }
  n ++;
  if(n > 10)exit(0);
 }
}
