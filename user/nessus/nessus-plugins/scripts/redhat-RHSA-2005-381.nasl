#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18196);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1287", "CVE-2005-1194");

 name["english"] = "RHSA-2005-381: nasm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated nasm package that fixes multiple security issues is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  NASM is an 80x86 assembler.

  Two stack based buffer overflow bugs have been found in nasm. An attacker
  could create an ASM file in such a way that when compiled by a victim,
  could execute arbitrary code on their machine. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the names CVE-2004-1287
  and CVE-2005-1194 to these issues.

  All users of nasm are advised to upgrade to this updated package, which
  contains backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-381.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nasm packages";
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
if ( rpm_check( reference:"nasm-0.98-8.EL21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98-8.EL21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98-8.EL21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.35-3.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-0.98.38-3.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-doc-0.98.38-3.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nasm-rdoff-0.98.38-3.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"nasm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1287", value:TRUE);
 set_kb_item(name:"CVE-2005-1194", value:TRUE);
}
if ( rpm_exists(rpm:"nasm-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1287", value:TRUE);
 set_kb_item(name:"CVE-2005-1194", value:TRUE);
}
if ( rpm_exists(rpm:"nasm-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1287", value:TRUE);
 set_kb_item(name:"CVE-2005-1194", value:TRUE);
}

set_kb_item(name:"RHSA-2005-381", value:TRUE);
