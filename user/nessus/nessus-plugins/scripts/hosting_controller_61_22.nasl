#
# (C) Tenable Network Security
#


if (description) {
  script_id(19255);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14302, 14393);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17915");
    script_xref(name:"OSVDB", value:"17916");
    script_xref(name:"OSVDB", value:"17917");
    script_xref(name:"OSVDB", value:"17918");
  }

  name["english"] = "Hosting Controller <= 6.1 Hotfix 2.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple vulnerabilities. 

Description :

According to its version number, the installation of Hosting
Controller on the remote host improperly allows an authenticated user
to add hosting plans to his account, to edit the details of his own or
anyone else's hosting plans, to view the folders of all resellers and
the web admin, to add domains with unlimited quotas, and to influence
SQL queries via the 'hostcustid' parameter of the 'plandetails.asp'
script. 

See also : 

http://securitytracker.com/alerts/2005/Jul/1014496.html
http://hostingcontroller.com/english/logs/hotfixlogv61_2_3.html

Solution : 

Apply Hotfix 2.3 or later for version 6.1.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:L/Au:R/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Hosting Controller <= 6.1 Hotfix 2.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("hosting_controller_detect.nasl");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check for Hosting Controller installs.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8887);
foreach port (ports) {
  ver = get_kb_item(string("www/", port, "/hosting_controller"));
  if (ver) {
    # nb: versions <= 6.1 hotfix 2.2 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([01]\.|2\.[0-2]))))") {
      security_note(port);
      if (!thorough_tests) exit(0);
    }
  }
}
