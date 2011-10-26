#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17169);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1183", "CVE-2004-1308");

 name["english"] = "RHSA-2005-035: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libtiff packages that fix various integer overflows are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team

  The libtiff package contains a library of functions for manipulating TIFF
  (Tagged Image File Format) image format files.

  infamous41md discovered integer overflow flaws in libtiff. An attacker
  could create a carefully crafted TIFF file in such a way that it could
  cause an application linked with libtiff to overflow a heap buffer when the
  file was opened by a victim. Due to the nature of the overflow it is
  unlikely that it is possible to use this flaw to execute arbitrary code.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1308 to this issue.

  Dmitry V. Levin discovered an integer overflow flaw in libtiff. An
  attacker could create a carefully crafted TIFF file in such a way that it
  could cause an application linked with libtiff to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1183 to this issue.

  All users are advised to upgrade to these updated packages, which contain
  backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-035.html
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
if ( rpm_check( reference:"libtiff-3.6.1-8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libtiff-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1183", value:TRUE);
 set_kb_item(name:"CVE-2004-1308", value:TRUE);
}

set_kb_item(name:"RHSA-2005-035", value:TRUE);
