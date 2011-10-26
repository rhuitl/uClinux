#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:055
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14039);
 script_bugtraq_id(7536);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0256");
 
 name["english"] = "MDKSA-2003:055: kopete";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:055 (kopete).


A vulnerability was discovered in versions of kopete, a KDE instant messenger
client, prior to 0.6.2. This vulnerabiliy is in the GnuPG plugin that allows for
users to send each other GPG-encrypted instant messages. The plugin passes
encrypted messages to gpg, but does no checking to sanitize the commandline
passed to gpg. This can allow remote users to execute arbitrary code, with the
permissions of the user running kopete, on the local system.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:055
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kopete package";
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
if ( rpm_check( reference:"kopete-0.6.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkopete1-0.6.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kopete-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0256", value:TRUE);
}
