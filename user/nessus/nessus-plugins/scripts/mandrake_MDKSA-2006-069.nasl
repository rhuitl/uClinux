#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21206);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1629");
 
 name["english"] = "MDKSA-2006:069: openvpn";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:069 (openvpn).



A vulnerability in OpenVPN 2.0 through 2.0.5 allows a malicious server to
execute arbitrary code on the client by using setenv with the LD_PRELOAD
environment variable. Updated packages have been patched to correct this issue
by removing setenv support.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:069
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openvpn package";
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
if ( rpm_check( reference:"openvpn-2.0.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"openvpn-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1629", value:TRUE);
}
