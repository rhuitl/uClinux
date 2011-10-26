#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14363);
 script_bugtraq_id(11018);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "INL ulog-php SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to SQL
injection attacks. 

Description :

The remote host is running ulog-php, a firewall log analysis interface
written in PHP. 

There is a SQL injection vulnerability in the remote interface, in the
'port.php' script that may allow an attacker to insert arbitrary SQL
statements into the remote database.  An attacker may exploit this
flaw to add bogus statements to the remote log database or to remove
arbitrary log entries from the database, thus clearing his tracks. 

Solution : 

Upgrade to ulog-php 0.8.2 or later.

Risk factor: 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a SQL injection vulnerability in ulog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

function check(loc)
{
 local_var req, r;

 req = http_get(item:string(loc, "/port.php?proto=tcp'"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('select ip_saddr,ip_daddr,ip_protocol,oob_time_sec,tcp_sport,tcp_dport,udp_sport,udp_dport,oob_prefix,id' >< r )
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}

