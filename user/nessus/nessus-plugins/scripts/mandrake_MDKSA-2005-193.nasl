#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:193-2
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20435);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3184", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3245", "CVE-2005-3246", "CVE-2005-3247", "CVE-2005-3248", "CVE-2005-3249", "CVE-2005-3313");
 
 name["english"] = "MDKSA-2005:193-2: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:193-2 (ethereal).



Ethereal 0.10.13 is now available fixing a number of security vulnerabilities
in various dissectors: - the ISAKMP dissector could exhaust system memory - the
FC-FCS dissector could exhaust system memory - the RSVP dissector could exhaust
system memory - the ISIS LSP dissector could exhaust system memory - the IrDA
dissector could crash - the SLIMP3 dissector could overflow a buffer - the BER
dissector was susceptible to an infinite loop - the SCSI dissector could
dereference a null pointer and crash - the sFlow dissector could dereference a
null pointer and crash - the RTnet dissector could dereference a null pointer
and crash - the SigComp UDVM could go into an infinite loop or crash - the X11
dissector could attempt to divide by zero - if SMB transaction payload
reassembly is enabled the SMB dissector could crash (by default this is
disabled) - if the 'Dissect unknown RPC program numbers' option was enabled,
the ONC RPC dissector might be able to exhaust system memory (by default this
is disabled) - the AgentX dissector could overflow a buffer - the WSP dissector
could free an invalid pointer - iDEFENSE discovered a buffer overflow in the
SRVLOC dissector The new version of Ethereal is provided and corrects all of
these issues. An infinite loop in the IRC dissector was also discovered and
fixed after the 0.10.13 release. The updated packages include the fix.

Update:

A permissions problem on the /usr/share/ethereal/dtds directory caused errors
when ethereal started as a non-root user. This update corrects the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:193-2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.13-0.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.13-0.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.13-0.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.13-0.4.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.13-0.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.13-0.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.13-0.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.13-0.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.2")
 || rpm_exists(rpm:"ethereal-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3184", value:TRUE);
 set_kb_item(name:"CVE-2005-3241", value:TRUE);
 set_kb_item(name:"CVE-2005-3242", value:TRUE);
 set_kb_item(name:"CVE-2005-3243", value:TRUE);
 set_kb_item(name:"CVE-2005-3244", value:TRUE);
 set_kb_item(name:"CVE-2005-3245", value:TRUE);
 set_kb_item(name:"CVE-2005-3246", value:TRUE);
 set_kb_item(name:"CVE-2005-3247", value:TRUE);
 set_kb_item(name:"CVE-2005-3248", value:TRUE);
 set_kb_item(name:"CVE-2005-3249", value:TRUE);
 set_kb_item(name:"CVE-2005-3313", value:TRUE);
}
