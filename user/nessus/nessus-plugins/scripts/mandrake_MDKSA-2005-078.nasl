#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:078
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18171);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0194", "CVE-2005-0626", "CVE-2005-0718");
 
 name["english"] = "MDKSA-2005:078: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:078 (squid).



Squid 2.5, when processing the configuration file, parses empty Access Control
Lists (ACLs), including proxy_auth ACLs without defined auth schemes, in a way
that effectively removes arguments, which could allow remote attackers to
bypass intended ACLs if the administrator ignores the parser warnings.
(CVE-2005-0194)

Race condition in Squid 2.5.STABLE7 to 2.5.STABLE9, when using the Netscape
Set-Cookie recommendations for handling cookies in caches, may cause Set-Cookie
headers to be sent to other users, which allows attackers to steal the related
cookies. (CVE-2005-0626)

Squid 2.5.STABLE7 and earlier allows remote attackers to cause a denial of
service (segmentation fault) by aborting the connection during a (1) PUT or (2)
POST request, which causes Squid to access previosuly freed memory.
(CVE-2005-0718)

In addition, due to subtle bugs in the previous backported updates of squid
(Bugzilla #14209), all the squid-2.5 versions have been updated to
squid-2.5.STABLE9 with all the STABLE9 patches from the squid developers.

The updated packages are patched to fix these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:078
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE6-2.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.0")
 || rpm_exists(rpm:"squid-", release:"MDK10.1")
 || rpm_exists(rpm:"squid-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0194", value:TRUE);
 set_kb_item(name:"CVE-2005-0626", value:TRUE);
 set_kb_item(name:"CVE-2005-0718", value:TRUE);
}
