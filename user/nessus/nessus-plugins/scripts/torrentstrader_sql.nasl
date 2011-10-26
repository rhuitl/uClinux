#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14615);
 script_bugtraq_id(11087);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "TorrentTrader SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running TorrentTrader, a web-based BitTorrent tracker.

The remote version of this software is vulnerable to a SQL injection
vulnerability which may allow an attacker to inject arbitrary SQL statements
in the remote database.


Solution : Upgrade to the latest version of this software
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of SQL injection in TorrentTrader";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

# TorrentTrader must be installed under /
req = http_get(item:"/download.php?id='", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( r == NULL )exit(0);
if(egrep(pattern:".*mysql_result\(\).*MySQL.*download\.php", string:r) )
{
 	security_hole(port);
	exit(0);
}
