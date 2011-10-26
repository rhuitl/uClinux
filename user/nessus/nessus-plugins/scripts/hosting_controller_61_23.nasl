#
# (C) Tenable Network Security
#


if (description) {
  script_id(19755);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3038");
  script_bugtraq_id(14840);

  name["english"] = "Hosting Controller <= 6.1 Hotfix 2.3 Information Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server may give customer PHP scripts access to arbitrary
files. 

Description : 

According to its version number, the installation of Hosting
Controller on the remote host may allow customers to use PHP scripts
to gain access to files outside of their directory, including those
belonging to other customers, resellers, or the system itself. 

See also :

http://www.nessus.org/u?6d705b82
http://hostingcontroller.com/english/logs/hotfixlogv61_2_4.html

Solution :

Apply Hotfix 2.4 or later for version 6.1 or set PHP's 'open_basedir'
parameter for each customer's site via the Windows registry. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for information disclosure vulnerability in Hosting Controller <= 6.1 Hotfix 2.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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
    # nb: versions <= 6.1 hotfix 2.3 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([01]\.|2\.[0-3]))))") {
      security_warning(port);
      if (!thorough_tests) exit(0);
    }
  }
}
