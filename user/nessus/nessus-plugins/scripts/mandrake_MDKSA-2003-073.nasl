#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:073-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14056);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(7550);
 script_cve_id("CVE-2003-0282");
 
 name["english"] = "MDKSA-2003:073-1: unzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:073-1 (unzip).


A vulnerability was discovered in unzip 5.50 and earlier that allows attackers
to overwrite arbitrary files during archive extraction by placing non-printable
characters between two '.' characters. These invalid characters are filtered
which results in a '..' sequence.
The patch applied to these packages prevents unzip from writing to parent
directories unless the '-:' command line option is used.
Update:
Ben Laurie found that the original patch used to fix this issue missed a case
where the path component included a quoted slash. An updated patch was used to
build these packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:073-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the unzip package";
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
if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK8.2")
 || rpm_exists(rpm:"unzip-", release:"MDK9.0")
 || rpm_exists(rpm:"unzip-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0282", value:TRUE);
}
