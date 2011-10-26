#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13916);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:008: jmcce";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:008 (jmcce).


A problem exists in the jmcce program that is used for Chinese text on the
console. jmcce is installed setuid root and places log files in /tmp; because
jmcce does not perform suitable checking on the files it writes to and because
it uses a predictable logfile name, an attacker could exploit this to
arbitrarily overwrite any file on the system.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:008
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the jmcce package";
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
if ( rpm_check( reference:"jmcce-1.3-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
