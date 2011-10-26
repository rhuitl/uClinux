#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17306);
 script_bugtraq_id(12740);
 script_version("$Revision: 1.2 $");
 name["english"] = "BRT CopperExport XP_Publish.PHP SQL Injection Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CopperExport, a plugin which allows an iPhoto user
to export images to a Coppermine gallery.

The remote version of this software is vulnerable to a SQL injection 
vulnerability which may allow attackers to execute arbitrary SQL commands
against the remote database.

Solution : Upgrade to CopperExport 0.2.1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in CopperExport";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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
  req = http_get(item:dir + "/ChangeLog", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("initial release of CopperExport." ><  buf &&
     "Version 0.2.1" >!< buf )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) check( dir : dir );
