#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16218);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0991");
 
 name["english"] = "MDKSA-2005:009: mpg123";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:009 (mpg123).



A vulnerability in mpg123's ability to parse frame headers in input streams
could allow a malicious file to exploit a buffer overflow and execute arbitray
code with the permissions of the user running mpg123.

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:009
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mpg123 package";
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
if ( rpm_check( reference:"mpg123-0.59r-22.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-22.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK10.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0991", value:TRUE);
}
