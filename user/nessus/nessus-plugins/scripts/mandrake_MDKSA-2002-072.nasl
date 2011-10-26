#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:072
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13972);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1157");
 
 name["english"] = "MDKSA-2002:072: mod_ssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:072 (mod_ssl).


A cross-site scripting vulnerability was discovered in mod_ssl by Joe Orton.
This only affects servers using a combination of wildcard DNS and
'UseCanonicalName off' (which is not the default in Mandrake Linux). With this
setting turned off, Apache will attempt to use the hostname:port that the client
supplies, which is where the problem comes into play. With this setting turned
on (the default), Apache constructs a self-referencing URL and will use
ServerName and Port to form the canonical name.
It is recommended that all users upgrade, regardless of the setting of the
'UseCanonicalName' configuration option.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:072
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_ssl package";
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
if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.7-3.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.10-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK7.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1157", value:TRUE);
}
