#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12258);
 script_cve_id("CVE-2004-2556", "CVE-2004-2557");
 script_bugtraq_id(10459);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6743");
 }
 script_version("$Revision: 1.9 $");
 name["english"] = "NetGear Hidden Password Check";
 script_name(english:name["english"]);
 desc["english"] = "
NetGear ships at least one device with a builtin administrator
account.  This account cannot be changed via the configuration
interface and enables a remote attacker to control the NetGear
device.  

To duplicate this error, simply point your browser to a vulnerable
machine, and log in (when prompted) with 
userid = super
password = 5777364

or 

userid = superman
password = 21241036

See also : http://archives.neohapsis.com/archives/bugtraq/2004-06/0036.html
           http://archives.neohapsis.com/archives/bugtraq/2004-06/0077.html
           http://kbserver.netgear.com/kb_web_files/n101383.asp
Solution: Contact vendor for a fix.  As a temporary workaround,
disable the webserver or filter the traffic to the NetGear webserver
via an upstream firewall. 

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "NetGear Hidden Password Check";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) 
	exit(0); 

init = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n");

auth[0] = "c3VwZXJtYW46MjEyNDEwMzY=";
auth[1] = "c3VwZXI6NTc3NzM2NA==";




reply = http_keepalive_send_recv(data:init, port:port, embedded:TRUE);
if ( reply == NULL ) exit(0);

if ( egrep(pattern:"HTTP/.* 40[13] ", string:reply ) )
{
     for ( i = 0 ; auth[i] ; i ++ )
     {
	req = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), 
		     "\r\nAuthorization: Basic ", auth[i], "\r\n\r\n");

	reply = http_keepalive_send_recv(data:req, port:port, embedded:TRUE);
	if ( (egrep(string:reply, pattern:"^HTTP/1\.* 200 OK")) && 
	   ("NETGEAR" >< reply) )
	{
		security_hole(port);
		exit(0);
	}
      }
}

