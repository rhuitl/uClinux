#
# (C) Tenable Network Security
#


if (description) {
  script_id(18288);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-0927");
  script_bugtraq_id(12938);

  name["english"] = "WebAPP File Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is affected by an
information disclosure vulnerability. 

Description :

According to its banner, the remote host is running a version of
WebAPP that suffers from an unspecified file disclosure vulnerability. 
An attacker may be able to use this flaw to disclose the contents of
'dat' files. 

See also : 

http://www.web-app.org/cgi-bin/index.cgi?action=viewnews&id=195

Solution : 

Apply the March 2005 Security Update.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file disclosure vulnerability in WebAPP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("webapp_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: versions below 0.9.9.2.1 are vulnerable.
  if (ver =~ "^0\.([0-8]([^0-9]|$)|9([^0-9.]|$|\.[0-8]([^0-9]|$)|\.9([^0-9.]|$|\.[01]([^0-9]|$)|\.2([^0-9.]|$|\.1[^0-9]))))")
    security_note(port);
}
