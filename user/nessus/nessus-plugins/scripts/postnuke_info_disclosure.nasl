#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if (description)
{
 script_id(11482);
 script_version("$Revision: 1.7 $");
 script_name(english:"Post-Nuke information disclosure");
 desc["english"] = "
The remote host is running post-nuke. It is possible to use it
to determine the full path to its installation on the server
or the name of the database used, by doing a request like :

/modules.php?op=modload&name=Members_List&file=index&letter=All&sortby=foobar

An attacker may use these flaws to gain a more intimate knowledge
of the remote host.

Solution : Change the members list privileges to admins only, or disable
the members list module completely
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the opendir.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
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

req = http_get(item:string(dir, "/modules.php?op=modload&name=Members_List&file=index&letter=All&sortby=foobar"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if("Program: /" >< res && "Database: " >< res && "Unknown column 'foobar'" >< res)
    	security_warning(port);
