#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17653);
 script_cve_id("CVE-2005-0948", "CVE-2005-0949");
 script_bugtraq_id(12936);
 script_version("$Revision: 1.3 $");
 name["english"] = "ASP PortalApp SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ASP PortalApp, a web application software
written in ASP.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to the latest version of this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  req = http_get(item:dir + "/ad_click.asp?banner_id='", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("Microsoft JET"  >< buf && '80040e14' >< buf  )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);
check( dir:"" );
