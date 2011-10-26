#
# (C) Tenable Network Security
#


if (description) {
  script_id(19552);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2554");
  script_bugtraq_id(14549);

  name["english"] = "ePolicy Orchestrator Local Information Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is prone to an information disclosure
vulnerability. 

Description :

The remote host is running ePolicy Orchestrator / ProtectionPilot, a
system security management solution from McAfee. 

According to its banner, the Common Management Agent (CMA) associated
with ePolicy Orchestrator / ProtectionPilot on the remote host can be
used by local users to view files residing on the same partition as
the affected application with LocalSystem level privileges by creating
symbolic links in the agent's web root directory.  This may enable
them to read files to which they would not otherwise have access. 

See also : 

http://reedarvin.thearvins.com/20050811-01.html
http://www.nessus.org/u?4bed00fb

Solution : 

Apply CMA 3.5 Patch 4 as described in the vendor's advisory.

Risk factor : 

Low / CVSS Base Score : 2
(AV:L/AC:L/Au:NR/C:C/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for local information disclosure vulnerability in ePolicy Orchestrator";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8081);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# There's a problem if ...
if (
  # it looks like EPO and...
  '<?xml-stylesheet type="text/xsl" href="FrameworkLog.xsl"?>' >< res &&
  egrep(string:res, pattern:"^ +<Log component=.+</Log") &&
  # the version is below 3.5.0.508 (ie, 3.5.0 patch 4)
  egrep(string:res, pattern:"^ +<version>3\.([0-4]\..*|5\.0\.([0-4].*|50[0-7]))<")
) {
  security_note(port);
}
