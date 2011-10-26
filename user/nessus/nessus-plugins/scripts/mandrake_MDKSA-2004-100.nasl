#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:100
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14794);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0865", "CVE-2004-0805");
 
 name["english"] = "MDKSA-2004:100: mpg123";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:100 (mpg123).


A vulnerability in mpg123 was discovered by Davide Del Vecchio where certain
malicious mpg3/2 files would cause mpg123 to fail header checks, which could in
turn allow arbitrary code to be executed with the privileges of the user running
mpg123 (CVE-2004-0805).
As well, an older vulnerability in mpg123, where a response from a remote HTTP
server could overflow a buffer allocated on the heap, is also fixed in these
packages. This vulnerability could also potentially permit the execution of
arbitray code with the privileges of the user running mpg123 (CVE-2003-0865).


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:100
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mpg123 package";
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
if ( rpm_check( reference:"mpg123-0.59r-21.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-21.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK10.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0865", value:TRUE);
 set_kb_item(name:"CVE-2004-0805", value:TRUE);
}
