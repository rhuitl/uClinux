#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:116
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14098);
 script_bugtraq_id(9210);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0963");
 
 name["english"] = "MDKSA-2003:116: lftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:116 (lftp).


A buffer overflow vulnerability was discovered by Ulf Harnhammar in the lftp FTP
client when connecting to a web server using HTTP or HTTPS and using the 'ls' or
'rels' command on specially prepared directory. This vulnerability exists in
lftp versions 2.3.0 through 2.6.9 and is corrected upstream in 2.6.10.
The updated packages are patched to protect against this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:116
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lftp package";
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
if ( rpm_check( reference:"lftp-2.6.0-1.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.4-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.6-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"lftp-", release:"MDK9.0")
 || rpm_exists(rpm:"lftp-", release:"MDK9.1")
 || rpm_exists(rpm:"lftp-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0963", value:TRUE);
}
