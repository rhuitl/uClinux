#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:086
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13984);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1344");
 
 name["english"] = "MDKSA-2002:086: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:086 (wget).


A vulnerability in all versions of wget prior to and including 1.8.2 was
discovered by Steven M. Christey. The bug permits a malicious FTP server to
create or overwriet files anywhere on the local file system by sending filenames
beginning with '/' or containing '/../'. This can be used to make vulnerable FTP
clients write files that can later be used for attack against the client
machine.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:086
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget package";
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
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK7.2")
 || rpm_exists(rpm:"wget-", release:"MDK8.0")
 || rpm_exists(rpm:"wget-", release:"MDK8.1")
 || rpm_exists(rpm:"wget-", release:"MDK8.2")
 || rpm_exists(rpm:"wget-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1344", value:TRUE);
}
