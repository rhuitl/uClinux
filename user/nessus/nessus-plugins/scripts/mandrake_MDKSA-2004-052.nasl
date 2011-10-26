#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:052
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14151);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:052: kolab-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:052 (kolab-server).


Luca Villani reported the disclosure of critical configuration information
within Kolab, the KDE Groupware server. The affected versions store OpenLDAP
passwords in plain text. The heart of Kolab is an engine written in Perl that
rewrites configuration for certain applications based on templates. The build()
function in the engine left slapd.conf world-readable exhibiting the OpenLDAP
root password.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:052
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kolab-server package";
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
if ( rpm_check( reference:"kolab-server-1.0-0.23.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
