#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14031);
 script_bugtraq_id(7321);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0173");
 
 name["english"] = "MDKSA-2003:047: xfsdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:047 (xfsdump).


A vulnerability was discovered in xfsdump by Ethan Benson related to filesystem
quotas on the XFS filesystem. When xfsdump runs xfsdq to save the quota
information into a file at the root of the filesystem being dumped, the file is
created in an unsafe manner.
A new option to xfsdq was added when fixing this vulnerability: '-f path'. This
specifies an output file to use instead of the default output stream. If the
file exists already, xfsdq will abort and if the file doesn't already exist, it
will be created with more appropriate access permissions.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:047
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xfsdump package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xfsdump-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xfsdump-2.0.3-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libdm0-2.0.5-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libdm0-devel-2.0.5-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xfsdump-2.0.3-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xfsdump-", release:"MDK8.2")
 || rpm_exists(rpm:"xfsdump-", release:"MDK9.0")
 || rpm_exists(rpm:"xfsdump-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0173", value:TRUE);
}
