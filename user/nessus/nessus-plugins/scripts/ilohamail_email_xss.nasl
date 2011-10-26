#
# (C) Tenable Network Security
#


if (description) {
  script_id(18050);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1120");
  script_bugtraq_id(13175);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15506");

  name["english"] = "IlohaMail Email Message Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is subject to
cross-site scripting attacks. 

Description :

Based on its version number, the installation of IlohaMail on the
remote host does not properly sanitize attachment file names, MIME
media types, and HTML / text e-mail messages.  An attacker can exploit
these vulnerabilities by sending a specially-crafted message to a user
which, when read using an affected version of IlohaMail, will allow
him to execute arbitrary HTML and script code in the user's browser
within the context of the affected web site. 

See also : 

http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=304525

Solution : 

Upgrade to IlohaMail version 0.8.14-rc3 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for email message cross-site scripting vulnerabilities in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("ilohamail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ilohamail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  # nb: versions 0.8.14-rc2 and earlier may be affected.
  if (ver =~ "^0\.([1-7].*|8\.([0-9]([^0-9]|$)|1([0-3]|4.*rc[12])))")
    security_note(port);
}
