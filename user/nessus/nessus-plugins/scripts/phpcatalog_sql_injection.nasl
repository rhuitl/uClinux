#
# (C) Tenable Network Security
#
#ref: http://xforce.iss.net/xforce/xfdb/14116
#     http://secunia.com/advisories/10516/
#

if(description)
{
 script_id(11969);
 script_bugtraq_id(9318);

 script_version("$Revision: 1.7 $");
 name["english"] = "PHPCatalog SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running PHPCatalog, a CGI suite
to handle on-line catalogues.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to PHPCatalog 2.6.10 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir)
{
  req = http_get(item:dir + "/index.php?id='", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("FROM phpc_catalog prod " >< buf )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
