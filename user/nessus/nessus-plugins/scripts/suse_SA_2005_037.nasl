#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19246);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:037: RealPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:037 (RealPlayer).


Various security problems were found in RealPlayer that allow a remote
attacker to execute code in the local player by providing handcrafted
files.

See http://service.real.com/help/faq/security/050623_player/EN/ too.

The following security bugs are listed:
- To fashion a malicious MP3 file to allow the overwriting of a local
file or execution of an ActiveX control on a customer's machine.

- To fashion a malicious RealMedia file which uses RealText to cause
a heap overflow to allow an attacker to execute arbitrary code on a
customer's machine.

- To fashion a malicious AVI file to cause a buffer overflow to allow
an attacker to execute arbitrary code on a customer's machine.

- Using default settings of earlier Internet Explorer browsers,
a malicious website could cause a local HTML file to be created and
then trigger an RM file to play which would then reference this local
HTML file. (Not applicable to Linux.)


The updated package fixes these problems.

These are tracked by the Mitre CVE IDs CVE-2005-1766 and CVE-2005-1277.

This bug affects all SUSE Linux versions including RealPlayer.

However, due to the binary only nature of RealPlayer we are only able
to provide fixed packages for SUSE Linux 9.2, 9.3 and Novell Linux
Desktop 9.

For the SUSE Linux versions containing RealPlayer 8 we are no longer

Solution : http://www.suse.de/security/advisories/2005_37_real_player.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the RealPlayer package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"RealPlayer-10.0.5-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.5-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
