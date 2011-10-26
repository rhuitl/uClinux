#
# (C) Tenable Network Security
#

if (description) {
  script_id(14700);
  script_bugtraq_id(11113);
  script_cve_id("CVE-2004-0787");
  script_version ("$Revision: 1.2 $"); 
  name["english"] = "OpenCA HTML Injection";
  script_name(english:name["english"]);
  desc["english"] = "
The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.2-RC2 are prone 
to a HTML injection vulnerability when processing user inputs into the web 
form frontend. This issue may permit an attacker to execute hostile HTML 
code in the context of another user.
 

Solution : Upgrade to the newest version of this software
Risk Factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the version of OpenCA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Copyright (C) Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

buf = http_get(item:"/cgi-bin/pub/pki?cmd=serverInfo", port:port);
res = http_keepalive_send_recv(port:port, data:buf);
if ( res == NULL ) exit(0);

str = egrep(pattern:"Server Information for OpenCA Server Version .*", string:res);
if ( str )
{
	version = ereg_replace(pattern:".*Server Information for OpenCA Server Version (.*)\)", string:str, replace:"\1");
	set_kb_item(name:"www/" + port + "/openca/version", value:version);
}

if ( egrep(pattern:"Server Information for OpenCA Server Version 0\.([0-8][^0-9]|9\.[0-2][^0-9])", string:str) ) security_warning(port);

