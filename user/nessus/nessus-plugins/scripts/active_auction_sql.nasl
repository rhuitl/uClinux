#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17989);
 script_cve_id("CVE-2005-1029", "CVE-2005-1030");
 script_bugtraq_id(13039, 13038, 13036, 13035, 13034, 13032);
 script_version("$Revision: 1.4 $");
 name["english"] = "ActiveAuction Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ActiveAuction, an auction software written in ASP.

The remote version of this software is vulnerable to various SQL injection and
cross site scripting issues.

Solution : Upgrade to the newest version of this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (make_list( cgi_dirs()))
{
 req = http_get(item:dir + "/activeauctionsuperstore/ItemInfo.asp?itemID=42'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"Microsoft.*ODBC.*80040e14", string:res ) )
  {
  security_hole(port);
  exit(0);
  }
}
