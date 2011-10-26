#
# (C) Tenable Network Security
#


if (description)
{
 script_id(15570);
 script_bugtraq_id(11529);
 script_version("$Revision: 1.3 $");

 script_name(english:"Post-Nuke Trojan Horse");
 desc["english"] = "
The remote host seems to be running a copy of a trojaned version of
the 'PostNuke' content management system.

Post-Nuke is a content management system in PHP whose main website has
been compromised between the 24th and 26th of October 2004. An attacker
modified some of the source code of the tool to execute arbitrary commands
remotely on the remote host, by passing arguments to the 'oops' parameter
of the file pnAPI.php.

Solution : Upgrade to the latest version of postnuke
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if post-nuke is trojaned");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


req = http_get(item:string(dir, "/includes/pnAPI.php?oops=id"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if( egrep(pattern:"uid=[0-9].*gid=[0-9]", string:res) ) 
    	security_hole(port);
