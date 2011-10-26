#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19827);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0967");

 name["english"] = "RHSA-2005-081: ghostscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ghostscript packages that fix a PDF output issue and a temporary
  file security bug are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Ghostscript is a program for displaying PostScript files or printing them
  to non-PostScript printers.

  A bug was found in the way several of Ghostscript\'s utility scripts created
  temporary files. A local user could cause these utilities to overwrite
  files that the victim running the utility has write access to. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2004-0967 to
  this issue.

  Additionally, this update addresses the following issue:

  A problem has been identified in the PDF output driver, which can cause
  output to be delayed indefinitely on some systems. The fix has been
  backported from GhostScript 7.07.

  All users of ghostscript should upgrade to these updated packages, which
  contain backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-081.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ghostscript packages";
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
if ( rpm_check( reference:"ghostscript-7.05-32.1.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-devel-7.05-32.1.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hpijs-1.3-32.1.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ghostscript-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0967", value:TRUE);
}

set_kb_item(name:"RHSA-2005-081", value:TRUE);
