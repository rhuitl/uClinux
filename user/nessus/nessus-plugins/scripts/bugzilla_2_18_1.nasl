#
# (C) Tenable Network Security
#


if (description) {
  script_id(18654);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(14198, 14200);

  name["english"] = "Bugzilla <= 2.18.1 / 2.19.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that suffers from
information disclosure vulnerabilities. 

Description :

According to its banner, the version of Bugzilla installed on the
remote host reportedly allows any user to change any flag on a bug,
even if they don't otherwise have access to the bug or rights to make
changes to it.  In addition, a private bug summary may be visible to
users if MySQL replication is used on the backend database. 

See also : 

http://www.bugzilla.org/security/2.18.1/

Solution : 

Upgrade to Bugzilla 2.18.2 / 2.20rc1 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Bugzilla <= 2.18.1 / 2.19.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the installed version.
ver = get_kb_item(string("www/", port, "/bugzilla/version"));
if (ver && ver =~ "^2\.1(7\..*|8\.[01]|9\.[0-3])") 
  security_warning(port);
