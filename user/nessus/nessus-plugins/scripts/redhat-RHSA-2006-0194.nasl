#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20856);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0941");

 name["english"] = "RHSA-2006-0194: gd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gd packages that fix several buffer overflow flaws are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gd package contains a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Several buffer overflow flaws were found in the way gd allocates memory.
  An attacker could create a carefully crafted image that could execute
  arbitrary code if opened by a victim using a program linked against the gd
  library. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  assigned the name CVE-2004-0941 to these issues.

  Users of gd should upgrade to these updated packages, which contain a
  backported patch and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0194.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gd packages";
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
if ( rpm_check( reference:"gd-2.0.28-4.4E.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-devel-2.0.28-4.4E.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-progs-2.0.28-4.4E.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gd-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0194", value:TRUE);
