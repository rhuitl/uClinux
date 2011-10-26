#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20481);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 name["english"] = "RHSA-2006-0163: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated CUPS packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  Chris Evans discovered several flaws in the way CUPS processes PDF files.
  An attacker could construct a carefully crafted PDF file that could cause
  CUPS to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project assigned the names CVE-2005-3624,
  CVE-2005-3625, CVE-2005-3626, and CVE-2005-3627 to these issues.

  All users of CUPS should upgrade to these updated packages, which contain
  backported patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0163.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cups-1.1.17-13.3.36", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.36", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.36", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cups-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}
if ( rpm_exists(rpm:"cups-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0163", value:TRUE);
