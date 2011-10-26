#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21736);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3147");
  script_bugtraq_id(18565);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"26693");

  script_name(english:"Hosting Controller <= 6.1 Hotfix 3.1 Privilege Escalation Vulnerability");
  script_summary(english:"Checks version of Hosting Controller");
 
 
  desc = "
Synopsis :

The remote web server contains an ASP application that suffers from a
privilege escalation vulnerability. 

Description :

According to its version number, the installation of Hosting
Controller on the remote host enables any authenticated user to gain
host admin privileges and view all his resellers and change their
passwords. 

See also :

http://www.milw0rm.com/exploits/1987
http://hostingcontroller.com/english/logs/hotfixlogv61_3_2.html

Solution :

Upgrade to version 6.1 if necessary and apply Hotfix 3.2 or later. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

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
    # nb: versions <= 6.1 hotfix 3.1 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([0-2]\.|3\.[01]))))") {
      security_warning(port);
      if (!thorough_tests) exit(0);
    }
  }
}
