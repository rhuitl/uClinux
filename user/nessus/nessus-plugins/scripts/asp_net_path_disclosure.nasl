#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10843);
 script_version ("$Revision: 1.8 $");
 name["english"] = "ASP.NET path disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
ASP.NET is vulnerable to a path disclosure vulnerability. This 
allows an attacker to determine where the remote web root is
physically stored in the remote file system, hence gaining
more information about the remote system.

Solution : There was no solution ready when this vulnerability was written;
Please contact the vendor for updates that address this vulnerability.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for ASP.NET Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 banner = get_http_banner(port:port);
 if ( "Microsoft-IIS" >!< sig ) exit(0);
 req = http_get(item:string("/a%5c.aspx"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 if("Server Error" >< r)
 {
  r = strstr(r, "Invalid file name");
  end = strstr(r, string("\n"));
  str = r - end;
  path = ereg_replace(pattern:".*Invalid file name for monitoring: (.*)</title>",
		    string:str,
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Z]:\\.*", icase:TRUE))security_warning(port);
  }
}
