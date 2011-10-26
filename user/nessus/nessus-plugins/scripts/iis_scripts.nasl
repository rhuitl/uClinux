#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10121);
 script_version ("$Revision: 1.18 $");

 name["english"] = "/scripts directory browsable";

 script_name(english:name["english"]);
 
 # Description
 desc["english"] = "The /scripts directory is browsable.
This gives an attacker valuable information about
which default scripts you have installed and also whether
there are any custom scripts present which may have vulnerabilities.

Solution : Disable directory browsing using the IIS MMC.

Risk factor : Medium";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Is /scripts/ listable ?";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_GATHER_INFO);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 
 # Family
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);
if(get_port_state(port))
{
 data = http_get(item:"/scripts", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  code = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "<title>/scripts";
  
  if((" 200 " >< code)&&(must_see >< buf))security_warning(port);
  http_close_socket(soc);
 }
}
