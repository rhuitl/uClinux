#
# (C) Tenable Network Security
#


if (description) {
  script_id(19309);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2428");
  script_bugtraq_id(14388, 14389);

  name["english"] = "Lotus Domino Server Information Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by multiple information disclosure
vulnerabilities. 

Description :

The remote host is running a version of Lotus Domino Server that is
prone to several information disclosure vulnerabilities. 
Specifically, users' password hashes and other data are included in
hidden fields in the public address book 'names.nsf' readable by
default by all users.  Moreover, Domino does not use a 'salt' to
compute password hashes, which makes it easier to crack passwords. 

See also : 

http://www.cybsec.com/vuln/default_configuration_information_disclosure_lotus_domino.pdf

Solution : 

Upgrade to Lotus Domino Server version 6.0.6 / 6.5.5 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for information disclosure vulnerabilities in Lotus Domino Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the version number in the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.(0\.[0-5]|[1-4]\.|5\.[0-4]))")
) {
  security_note(port);
}
