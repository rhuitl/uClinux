#
# (C) Tenable Network Security
#


if (description)
{
 script_id(13847);
 script_bugtraq_id(10807);
 script_version("$Revision: 1.2 $");

 script_name(english:"OpenDocMan Access Control Bypass");
 desc["english"] = "
The remote host is running OpenDocMan, an open source document management
system.

There is a flaw in the remote version of this software which may allow an
attacker with a given account to modify the content of some documents
he would otherwise not have access to.

Solution : Upgrade to OpenDocMan 1.2.0
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if OpenDocMan is present");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:string(dir, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL ) exit(0);
 
 if( "OpenDocMan" >< res && egrep(pattern:"<h5> OpenDocMan v(0\.|1\.[01]\.)", string:res) ) 
 {
    	security_warning(port);
	exit(0);
 }
}
