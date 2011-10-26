#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16159);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");

 name["english"] = "RHSA-2005-019: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libtiff packages that fix various integer overflows are now
  available.

  The libtiff package contains a library of functions for manipulating TIFF
  (Tagged Image File Format) image format files.

  iDEFENSE has reported an integer overflow bug that affects libtiff. An
  attacker who has the ability to trick a user into opening a malicious TIFF
  file could cause the application linked to libtiff to crash or possibly
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-1308 to this issue.

  Dmitry V. Levin reported another integer overflow in the tiffdump
  utility. An atacker who has the ability to trick a user into opening a
  malicious TIFF file with tiffdump could possibly execute arbitrary code.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1183 to this issue.

  All users are advised to upgrade to these updated packages, which contain
  backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-019.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff packages";
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
if ( rpm_check( reference:"libtiff-3.5.5-19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.5-19", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-22.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-22.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libtiff-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}
if ( rpm_exists(rpm:"libtiff-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}

set_kb_item(name:"RHSA-2005-019", value:TRUE);
