# tony@libpcap.net
# http://libpcap.net
#
# See the Nessus Scripts License for details

if(description)
{
  script_id(11444);
  script_bugtraq_id(5562);
  script_version ("$Revision: 1.9 $");
  script_cve_id("CVE-2002-0985", "CVE-2002-0986");

  name["english"] = "PHP Mail Function Header Spoofing Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PHP <= 4.2.2.

The mail() function does not properly sanitize user input.
This allows users to forge email to make it look like it is
coming from a different source other than the server.

Users can exploit this even if SAFE_MODE is enabled.

Solution : Contact your vendor for the latest PHP release.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for version of PHP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_copyright(english:"(C) tony@libpcap.net");
  if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
  else
  	script_dependencie("http_version.nasl", "redhat-RHSA-2002-214.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

if ( get_kb_item("CVE-2002-0985" ) ) exit(0);

port = get_http_port(default:80);


if(get_port_state(port)) {
  banner = get_http_banner(port:port);
  if(!banner)exit(0);

  if(egrep(pattern:".*PHP/([0-3]\..*|4\.[0-1]\..*|4\.2\.[0-2][^0-9])", string:banner)) {
    security_warning(port);
  }
}
 
