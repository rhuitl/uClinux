#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:004
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13912);
 script_bugtraq_id(3748);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0002");
 
 name["english"] = "MDKSA-2002:004: stunnel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:004 (stunnel).


All versions of stunnel from 3.15 to 3.21c are vulnerable to format string bugs
in the functions which implement smtp, pop, and nntp client negotiations. Using
stunnel with the '-n service' option and the '-c' client mode option, a
malicious server could use the format sting vulnerability to run arbitrary code
as the owner of the current stunnel process. Version 3.22 is not vulnerable to
this bug.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:004
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the stunnel package";
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
if ( rpm_check( reference:"stunnel-3.22-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"stunnel-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0002", value:TRUE);
}
