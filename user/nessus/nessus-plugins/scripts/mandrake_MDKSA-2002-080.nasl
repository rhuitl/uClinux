#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:080
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13978);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:080: kdenetwork";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:080 (kdenetwork).


The SuSE security team discovered two vulnerabilities in the KDE lanbrowsing
service during an audit. The LISa network daemon and 'reslisa', a restricted
version of LISa are used to identify servers on the local network by using the
URL type 'lan://' and 'rlan://' respectively. A buffer overflow was discovered
in the lisa daemon that can be exploited by an attacker on the local network to
obtain root privilege on a machine running the lisa daemon. Another buffer
overflow was found in the lan:// URL handler, which can be exploited by a remote
attacker to gain access to the victim user's account.
Only Mandrake Linux 9.0 comes with the LISa network daemon; all previous
versions do not contain the network daemon and are as such not vulnerable.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:080
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdenetwork package";
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
if ( rpm_check( reference:"kdenetwork-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lisa-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
