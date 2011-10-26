#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18476);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0427");

 name["english"] = "RHSA-2005-506: mikmod";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mikmod packages that fix a security issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  MikMod is a well known MOD music file player for UNIX-based systems.

  A buffer overflow bug was found in mikmod during the processing of archive
  filenames. An attacker could create a malicious archive that when opened by
  mikmod could result in arbitrary code execution. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0427
  to this issue.

  Users of mikmod are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-506.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mikmod packages";
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
if ( rpm_check( reference:"mikmod-3.1.6-14.EL21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-3.1.6-22.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-22.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-3.1.6-32.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-32.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mikmod-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0427", value:TRUE);
}
if ( rpm_exists(rpm:"mikmod-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0427", value:TRUE);
}
if ( rpm_exists(rpm:"mikmod-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2003-0427", value:TRUE);
}

set_kb_item(name:"RHSA-2005-506", value:TRUE);
