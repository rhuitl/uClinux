#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:054-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13956);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(5574);
 script_cve_id("CVE-2002-0384", "CVE-2002-0989");
 
 name["english"] = "MDKSA-2002:054-1: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:054-1 (gaim).


Versions of Gaim (an AOL instant message client) prior to 0.58 contain a buffer
overflow in the Jabber plug-in module. As well, a vulnerability was discovered
in the URL-handling code, where the 'manual' browser command passes an untrusted
string to the shell without reliable quoting or escaping. This allows an
attacker to execute arbitrary commands on the user's machine with the user's
permissions. Those using the built-in browser commands are not vulnerable.
Update:
The 8.1 package had an incorrect dependency on perl. This package has been
replaced with a proper package. Please note the differing md5 sums.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:054-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-0.59.1-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0384", value:TRUE);
 set_kb_item(name:"CVE-2002-0989", value:TRUE);
}
