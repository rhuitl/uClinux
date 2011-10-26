#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:204
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20128);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-2014");
 
 name["english"] = "MDKSA-2005:204: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:204 (wget).



Hugo Vazquez Carames discovered a race condition when writing output files in
wget. After wget determined the output file name, but before the file was
actually opened, a local attacker with write permissions to the download
directory could create a symbolic link with the name of the output file. This
could be exploited to overwrite arbitrary files with the permissions of the
user invoking wget. The time window of opportunity for the attacker is
determined solely by the delay of the first received data packet. The updated
packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:204
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget package";
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
if ( rpm_check( reference:"wget-1.9.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.9.1-5.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK10.1")
 || rpm_exists(rpm:"wget-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-2014", value:TRUE);
}
