#
# This script was written by Renaud Deraison
#
#
# See the Nessus Scripts License for details
#
# Ref: 
# From: Albert Puigsech Galicia <ripe@7a69ezine.org>
# Organization: 7a69
# To: bugtraq@securityfocus.com
# Subject: Multiple SQL injection on OpenBB forums


if(description)
{
 script_id(11550);
 script_bugtraq_id(7401, 7404, 7405);
 script_version("$Revision: 1.8 $");
 
 script_name(english:"OpenBB SQL injection");
 desc["english"] = "
The remote host seems to be running OpenBB, a forum management
system.

There is a bug which allows an attacker to inject SQL command
when passing a single quote (') to the CID argument of the
file index.php, as in : GET /index.php?CID='<sql query>

An attacker may use this flaw to gain credentials or to modify
your database.


Solution : If the remote host is running OpenBB, upgrade to the latest version
Risk factor : High";
 script_description(english:desc["english"]);
 script_summary(english:"Tests for SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d (make_list( "/openbb", cgi_dirs()))
{
 req = http_get(item:string(d, "/index.php?CID='"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
    egrep(pattern:"SELECT guest, forumid, title, lastthread, lastposter, lastposterid, lastthreadid, lastpost, moderators, description, type, postcount, threadcount", string:res)){
 	security_hole(port);
	exit(0);
 }
}
