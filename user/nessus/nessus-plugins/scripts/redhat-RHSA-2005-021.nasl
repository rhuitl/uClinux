#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18017);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 name["english"] = "RHSA-2005-021: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdegraphics packages that resolve multiple security issues in kfax
  are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team

  The kdegraphics package contains graphics applications for the K Desktop
  Environment.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect libtiff. The kfax application contains a copy of
  the libtiff code used for parsing TIFF files and is therefore affected by
  these bugs. An attacker who has the ability to trick a user into opening a
  malicious TIFF file could cause kfax to crash or possibly execute arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2004-0886 and CVE-2004-0804 to these issues.

  Additionally, a number of buffer overflow bugs that affect libtiff have
  been found. The kfax application contains a copy of the libtiff code used
  for parsing TIFF files and is therefore affected by these bugs. An attacker
  who has the ability to trick a user into opening a malicious TIFF file
  could cause kfax to crash or possibly execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0803 to this issue.

  Users of kfax should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-021.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics packages";
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
if ( rpm_check( reference:"kdegraphics-2.2.2-4.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-4.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-3.1.3-3.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.1.3-3.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}
if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}

set_kb_item(name:"RHSA-2005-021", value:TRUE);
