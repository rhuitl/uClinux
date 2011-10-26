#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20937);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0455");
 
 name["english"] = "Fedora Core 4 2006-116: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-116 (gnupg).

GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
creating digital signatures. GnuPG has advanced key management
capabilities and is compliant with the proposed OpenPGP Internet
standard described in RFC2440. Since GnuPG doesn't use any patented
algorithm, it is not compatible with any version of PGP2 (PGP2.x uses
only IDEA for symmetric-key encryption, which is patented worldwide).

Update Information:

The GNU Privacy Guard provides encryption and signing for
messages and arbitrary files, and implements the OpenPGP
standard as described by IETF RFC2440.

Version 1.4.2 of GnuPG would in some cases erroneously exit
with status 0 (signalling no errors) if it was invoked to
check a signature but found no signature to check. This
should be corrected in version 1.4.2.1.


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
if ( rpm_check( reference:"gnupg-1.4.2.1-1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gnupg-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0455", value:TRUE);
}
