#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20967);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:009: gpg,liby2util";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:009 (gpg,liby2util).


With certain handcraftable signatures GPG was returning a 0 (valid
signature) when used on command-line with option --verify.

This only affects GPG version 1.4.x, so it only affects SUSE Linux
9.3 and 10.0.  Other SUSE Linux versions are not affected.

This could make automated checkers, like for instance the patch file
verification checker of the YaST Online Update, pass malicious patch
files as correct.

This is tracked by the Mitre CVE ID CVE-2006-0455.

Also, the YaST Online Update script signature verification had used
a feature which was lost in gpg 1.4.x, making it possible to
supply any kind of script which would be thought correct. This would
also allow code execution.

Both attacks require an attacker either manipulating a YaST Online
Update mirror or manipulating the network traffic between the mirror
and your machine.


Solution : http://www.suse.de/security/advisories/2006_09_gpg.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpg,liby2util package";
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
if ( rpm_check( reference:"gpg-1.4.2-5.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liby2util-2.12.9-0.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liby2util-devel-2.12.9-0.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.4.0-4.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liby2util-2.11.7-0.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"liby2util-devel-2.11.7-0.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
