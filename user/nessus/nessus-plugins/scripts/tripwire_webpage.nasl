#
# (C) Tenable Network Security
#


if (description) {
  script_id(10743);
  script_version("$Revision: 1.12 $");

  name["english"] = "Tripwire for Webpages Information Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is using a product to monitor for changes in its
web pages. 

Description :

The remote host is running Tripwire for Webpages, a commercial product
to monitor for changes in web pages.  This information may prove useful
to anyone doing reconnaissance before launching an actual attack. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2001-08/0389.html

Solution :

Set Apache's 'ServerTokens' directive to 'Prod'.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for information disclosure vulnerability in Tripwire for Webpages";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: +Apache.+ Intrusion/[0-9]", string:banner)
) {
  security_note(port);
}
