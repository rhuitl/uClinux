#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:059
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14158);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0541");
 
 name["english"] = "MDKSA-2004:059: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:059 (squid).


A vulnerability exists in squid's NTLM authentication helper. This buffer
overflow can be exploited by a remote attacker by sending an overly long
password, thus overflowing the buffer and granting the ability to execute
arbitrary code. This can only be exploited, however, if NTLM authentication is
used. NTLM authentication is built by default in Mandrakelinux packages, but is
not enabled in the default configuration.
The vulnerability exists in 2.5.*-STABLE and 3.*-PRE. The provided packages are
patched to fix this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:059
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE4-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE1-7.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-3.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK9.1")
 || rpm_exists(rpm:"squid-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0541", value:TRUE);
}
