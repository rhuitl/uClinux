#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11198);
 script_version ("$Revision: 1.4 $");

 name["english"] = "BitKeeper remote command execution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version 3.0.x of BitKeeper.
Some versions of this service are known to allow anyone execute
arbitrary commands with the privileges of the BitKeeper daemon.

*** Nessus did not check for this vulnerability, but solely
*** relied on the banner of the remote server to issue this warning

Solution : Contact the vendor for a fix
See also : http://secunia.com/advisories/7854/
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote banner";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/BitKeeper");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8080);
if(!port) exit(0);
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 
 # The original exploit says that the bug can be exploited
 # by doing : http://host:port/diffs/foo.c@%27;echo%20%3Eiwashere%27?nav=index.html|src/|hist/foo.c
 # but since no repository is given, I'm a bit surprised. 
 # At this time, we'll simply yell if we see the banner
 #
 if("Server: bkhttp/0.3" >< banner)security_hole(port);
}
