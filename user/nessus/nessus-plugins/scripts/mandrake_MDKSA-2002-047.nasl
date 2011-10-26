#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13950);
 script_bugtraq_id(5344);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0638");
 
 name["english"] = "MDKSA-2002:047: util-linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:047 (util-linux).


Michal Zalewski found a vulnerability in the util-linux package with the chfn
utility. This utility allows users to modify some information in the /etc/passwd
file, and is installed setuid root. Using a carefully crafted attack sequence,
an attacker can exploit a complex file locking and modification race that would
allow them to make changes to the /etc/passwd file. To successfully exploit this
vulnerability and obtain privilege escalation, there is a need for some
administrator interaction, and the password file must over over 4kb in size; the
attacker's entry cannot be in the last 4kb of the file.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:047
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util-linux package";
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
if ( rpm_check( reference:"util-linux-2.10o-6.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.10o-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.10s-3.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11h-3.5mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"losetup-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11n-4.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"util-linux-", release:"MDK7.1")
 || rpm_exists(rpm:"util-linux-", release:"MDK7.2")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.0")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.1")
 || rpm_exists(rpm:"util-linux-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0638", value:TRUE);
}
