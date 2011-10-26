#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21093);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:014: gpg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:014 (gpg).


The GNU Privacy Guard (GPG) allows crafting a message which could
check out correct using '--verify', but would extract a different,
potentially malicious content when using '-o --batch'.

The reason for this is that a .gpg or .asc file can contain multiple
plain text and signature streams and the handling of these streams was
only possible when correctly following the gpg state.

The gpg '--verify' option has been changed to be way more strict than
before and fail on files with multiple signatures/blocks to mitigate
the problem of doing the common --verify checks and -o extraction.

This problem could be used by an attacker to remotely execute code
by using handcrafted YaST Online Patch files put onto a compromised
YOU mirror server and waiting for the user to run YOU.

This problem is tracked by the Mitre CVE ID CVE-2006-0049.

This is a different issue than the gpg signature checking problem for

Solution : http://www.suse.de/security/advisories/2006_14_gpg.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpg package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gpg-1.4.2-5.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.2.4-68.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.2.5-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.4.0-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
