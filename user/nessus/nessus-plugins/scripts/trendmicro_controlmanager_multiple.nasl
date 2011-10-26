#
# (C) Tenable Network Security
#


if (description) {
  script_id(20401);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1929");
  script_bugtraq_id(15865, 15866, 15867);
  script_xref(name:"OSVDB", value:"21771");
  script_xref(name:"OSVDB", value:"21772");

  script_name(english:"TrendMicro ControlManager Multiple Vulnerabilities");
  script_summary(english:"Checks for ControlManager version");
 
  desc = "
Synopsis :

The remote web server is vulnerable to remote code execution. 

Description :

The remote host appears to be running Trend Micro ControlManager. 

The version of ControlManager is vulnerable to a buffer overrun in CGI
programs which may allow a remote attacker to execute code in the
context of ControlManager.  This version is also vulnerable to a
denial of service (DoS) attack in the way it handles ISAPI requests. 

Note that ControlManager under Windows runs with SYSTEM privileges,
which means an attacker can gain complete control of the affected
host. 

See also :

http://www.trendmicro.com/download/product.asp?productid=7

Solution :

Apply TrendMicro Service Pack 5 for ControlManager 3.0.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

req = http_get (item:"/ControlManager/cgi-bin/dm_autologin_cgi.exe?-V", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if (res == NULL)
  exit(0);

# Service Pack 5 update the version 3.00.4208
res = strstr (res, "TMI-DM version:");
if (!res)
  exit (0);

if (egrep (pattern:"TMI-DM version: [0-2]\.", string:res))
{
 security_warning(port);
 exit (0);
}

if (egrep (pattern:"TMI-DM version: 3.0, build: .00.([0-9]+)", string:res))
{
 build = ereg_replace (pattern:"TMI-DM version: 3.0, build: .00.([0-9]+).*", string:res, replace:"\1");
 build = int (build);

 if (build < 4208)
   security_warning(port);
}
