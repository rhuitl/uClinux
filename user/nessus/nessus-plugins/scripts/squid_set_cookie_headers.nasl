#
# (C) Tenable Network Security
#


if (description) {
  script_id(19237);
  script_version ("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0626");
  script_bugtraq_id(12716);

  name["english"] = "Squid Proxy Set-Cookie Headers Information Disclosure Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote proxy server is affected by an information disclosure
issue. 

Description :

The remote Squid caching proxy, according to its banner, is prone to
an information disclosure vulnerability.  Due to a race condition,
Set-Cookie headers may leak to other users if the requested server
employs the deprecated Netscape Set-Cookie specifications with regards
to how cacheable content is handled.

See also :

http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE9-setcookie

Solution : 

Apply the patch referenced in the vendor URL above or upgrade to
version 2.5 STABLE10 or later. 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Set-Cookie headers information disclosure vulnerability in Squid";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  family["english"] = "Misc."; 
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
  script_dependencies("find_service.nes");
  script_require_ports("Services/http_proxy",3128, 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/http_proxy");
if (!port) {
  if (get_port_state(3128)) port = 3128;
  else port = 8080;
}

if (get_port_state(port)) {
  soc = open_sock_tcp(port);
  if (soc) {
    req = http_get(item:"/", port:port);
    res = http_keepalive_send_recv(data:req, port:port);
    if (egrep(pattern:"Squid/2\.([0-4]\.|5\.STABLE[0-9][^0-9])", string:res))
      security_note(port);
  }
}
