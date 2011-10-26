#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:050
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17279);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0372");
 
 name["english"] = "MDKSA-2005:050: gftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:050 (gftp).



A vulnerability in gftp could allow a malicious FTP server to overwrite files
on the local system as the user running gftp due to improper handling of
filenames containing slashes.

The updated packages are patched to deal with these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:050
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gftp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gftp-2.0.16-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gftp-2.0.17-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gftp-", release:"MDK10.0")
 || rpm_exists(rpm:"gftp-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0372", value:TRUE);
}
