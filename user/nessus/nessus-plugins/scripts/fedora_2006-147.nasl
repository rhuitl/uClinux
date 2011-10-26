#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21076);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0049");
 
 name["english"] = "Fedora Core 4 2006-147: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-147 (gnupg).

GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
creating digital signatures. GnuPG has advanced key management
capabilities and is compliant with the proposed OpenPGP Internet
standard described in RFC2440. Since GnuPG doesn't use any patented
algorithm, it is not compatible with any version of PGP2 (PGP2.x uses
only IDEA for symmetric-key encryption, which is patented worldwide).

Update Information:

Tavis Ormandy discovered a flaw in the way GnuPG verifies
cryptographically signed data with inline signatures. It is
possible for an attacker to add unsigned text to a signed
message in such a way so that when the signed text is
extracted, the unsigned text is extracted as well, appearing
as if it had been signed.  The Common Vulnerabilities and
Exposures project assigned the name CVE-2006-0049 to this issue.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gnupg-1.4.2.2-1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gnupg-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0049", value:TRUE);
}
