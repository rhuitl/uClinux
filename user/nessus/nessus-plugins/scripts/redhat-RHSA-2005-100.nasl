#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17186);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0088");

 name["english"] = "RHSA-2005-100: mod_python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mod_python package that fixes a security issue in the publisher
  handle is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mod_python is a module that embeds the Python language interpreter within
  the Apache web server, allowing handlers to be written in Python.

  Graham Dumpleton discovered a flaw affecting the publisher handler of
  mod_python, used to make objects inside modules callable via URL.
  A remote user could visit a carefully crafted URL that would gain access to
  objects that should not be visible, leading to an information leak. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0088 to this issue.

  Users of mod_python are advised to upgrade to this updated package,
  which contains a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-100.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_python packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mod_python-3.1.3-5.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mod_python-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0088", value:TRUE);
}

set_kb_item(name:"RHSA-2005-100", value:TRUE);
