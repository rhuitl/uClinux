#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10405);
 script_bugtraq_id(1174);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0413");
 name["english"] = "shtml.exe reveals full path";
 script_name(english:name["english"]);
 
 desc["english"] = "
The shtml.exe CGI which comes with FrontPage 2000
reveals the full path to the remote web root when
it is given a non-existent file as an argument.

This is useful to an attacker who can gain more
knowledge against the remote host.

Solution : Install Windows 2000 SP3
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Retrieve the real path using shtml.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
  req = http_get(item:"/_vti_bin/shtml.exe/nessus_test.exe", port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if ( ! result ) exit(0);
  if("no such file or folder" >< result)
   {
    result = tolower(result);
    str = strstr(result, "not open");
    if(egrep(string:str, pattern:"[a-z]:\\.*", icase:TRUE))
    {
     security_warning(port);
    }
  }
}

