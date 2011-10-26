#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:079
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13977);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:079: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:079 (kdelibs).


Vulnerabilities were discovered in the KIO subsystem support for various network
protocols. The implementation of the rlogin protocol affects all KDE versions
from 2.1 up to 3.0.4, while the flawed implementation of the telnet protocol
only affects KDE 2.x. They allow a carefully crafted URL in an HTML page, HTML
email, or other KIO-enabled application to execute arbitrary commands as the
victim with their privilege.
The KDE team provided a patch for KDE3 which has been applied in these packages.
No patch was provided for KDE2, however the KDE team recommends disabling both
the rlogin and telnet KIO protocols. This can be accomplished by removing, as
root, the following files: /usr/share/services/telnet.protocol and
/usr/share/services/rlogin.protocol. If either file also exists in a user's
~/.kde/share/services directory, they should likewise be removed.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:079
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-3.0.3-30.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.0.3-30.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
