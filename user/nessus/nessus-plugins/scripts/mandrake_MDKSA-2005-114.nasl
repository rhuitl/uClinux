#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:114
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18676);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-2068", "CVE-2005-1453", "CVE-2005-1911");
 
 name["english"] = "MDKSA-2005:114: leafnode";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:114 (leafnode).



A number of vulnerabilities in the leafnode NNTP server package have been
found:

A vulnerability in the fetchnews program that could under some circumstances
cause a wait for input that never arrives, which in turn would cause fetchnews
to hang (CVE-2004-2068).

Two vulnerabilities in the fetchnews program can cause fetchnews to crash when
the upstream server closes the connection and leafnode is receiving an article
header or an article body, which prevent leafnode from querying other servers
that are listed after that particular server in the configuration file
(CVE-2005-1453).

Finally, another vulnerability in the fetchnews program could also cuase a wait
for input that never arrives, causing fetchnews to hang (CVE-2005-1911).

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:114
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the leafnode package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"leafnode-1.10.4-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"leafnode-1.10.4-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"leafnode-", release:"MDK10.1")
 || rpm_exists(rpm:"leafnode-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-2068", value:TRUE);
 set_kb_item(name:"CVE-2005-1453", value:TRUE);
 set_kb_item(name:"CVE-2005-1911", value:TRUE);
}
