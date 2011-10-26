#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22254);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3918");
  script_bugtraq_id(19661);

  script_name(english:"Expect Header Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for an XSS flaw involving Expect Headers");

  desc = "
Synopsis :

The remote web server is vulnerable to a cross-site scripting attack. 

Description :

The remote web server fails to sanitize the contents of an 'Expect'
request header before using it to generate dynamic web content.  An
unauthenticated remote attacker may be able to leverage this issue to
launch cross-site scripting attacks against the affected service,
perhaps through specially-crafted ShockWave (SWF) files. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2006-05/0151.html
http://archives.neohapsis.com/archives/bugtraq/2006-05/0441.html
http://archives.neohapsis.com/archives/bugtraq/2006-07/0425.html
http://www.apache.org/dist/httpd/CHANGES_2.2
http://www.apache.org/dist/httpd/CHANGES_2.0
http://www.apache.org/dist/httpd/CHANGES_1.3
http://www-1.ibm.com/support/docview.wss?uid=swg1PK24631

Solution :

Check with the vendor for an update to the web server.  For Apache,
the issue is reportedly fixed by versions 1.3.35 / 2.0.57 / 2.2.2. For
IBM HTTP Server, upgrade to 6.0.2.13 / 6.1.0.1. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("raw.inc");


if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Generate a request to exploit the flaw.
exploit = string(SCRIPT_NAME, " testing for BID 19661 <test>");
req = string(
  "GET / HTTP/1.1\r\n",
  "Accept: */*\r\n",
  "Accept-Language: en-us\r\n",
  "Expect: ", exploit, "\r\n",
  "Accept-Encoding: gzip, deflate\r\n",
  "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
  "Host: ", get_host_ip(), "\r\n",
  "Connection: Keep-Alive\r\n",
  "\r\n"
);


# Send the request but don't worry about the response.
filter = string(
  "tcp and ",
  "src host ", get_host_ip(), " and ",
  "src port ", port, " and ",
  "dst port ", get_source_port(soc)
);
res = send_capture(socket:soc, data:req, pcap_filter:filter);
if (res == NULL) exit(0);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0);


# Half-close the connection.
#
# nb: the server sends a 417 response only after the connection is
#     closed; a half-close allows us to receive the resposne.
ip = ip();
seq = get_tcp_element(tcp:res, element:"th_ack");
tcp = tcp(
  th_dport : port,
  th_sport : get_source_port(soc),
  th_seq   : seq,
  th_ack   : seq,
  th_win   : get_tcp_element(tcp:res, element:"th_win"),
  th_flags : TH_FIN|TH_ACK
);
halfclose = mkpacket(ip, tcp);
send_packet(halfclose, pcap_active:FALSE);


# There's a problem if we see our exploit in the response.
res = recv(socket:soc, length:1024);
if (res && "417 Expectation Failed" >< res && exploit >< res) 
  security_note(port);


close(soc);
