#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16304);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1154");
 
 name["english"] = "SUSE-SA:2004:045: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:045 (samba).


The Samba developers informed us about several potential integer overflow
issues in the Samba 2 and Samba 3 code.
This update adds constraints to the Samba server code which protects it
from using values from untrusted sources as operands in arithmetic
operations to determine heap memory space needed to copy data.
Without these limitations a remote attacker may be able to overflow the
heap memory of the process and to overwrite vital information structures
which can be abused to execute arbitrary code.



Solution : http://www.suse.de/security/advisories/2004_45_samba.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"samba-2.2.8a-230", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-230", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.2a-283", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-230", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-230", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.2a-283", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-2.2.8a-230", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-2.2.8a-230", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-230", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-230", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.2a-283", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-2.2.8a-230", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-2.2.8a-230", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.9-2.1.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.9-2.1.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.5-11.7.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-3.0.9-2.1.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-3.0.9-2.1.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"SUSE8.1")
 || rpm_exists(rpm:"samba-", release:"SUSE8.2")
 || rpm_exists(rpm:"samba-", release:"SUSE9.0")
 || rpm_exists(rpm:"samba-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-1154", value:TRUE);
}
