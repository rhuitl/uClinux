#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:078
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14061);
 script_bugtraq_id(8680);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0577");
 
 name["english"] = "MDKSA-2003:078: mpg123";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:078 (mpg123).


A vulnerability in the mpg123 mp3 player could allow local and/or remote
attackers to cause a DoS and possibly execute arbitrary code via an mp3 file
with a zero bitrate, which causes a negative frame size.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:078
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
if ( rpm_check( reference:"mpg123-0.59r-17.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-17.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK9.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0577", value:TRUE);
}
