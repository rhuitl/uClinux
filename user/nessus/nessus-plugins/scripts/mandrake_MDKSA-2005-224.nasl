#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:224
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20455);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4077");
 
 name["english"] = "MDKSA-2005:224: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:224 (curl).



Stefan Esser discovered that libcurl's URL parser function can have a malloced
buffer overflows in two ways if given a too long URL. It cannot be triggered by
a redirect, which makes remote exploitation unlikely, but can be passed
directly to libcurl (allowing for local exploitation) and could also be used to
break out of PHP's safe_mode/ open_basedir. This vulnerability only exists in
libcurl and curl 7.11.2 up to and including 7.15.0, which means that Corporate
Server 2.1 and Corporate 3.0 are not vulnerable. The updated packages have been
patched to correct the problem. As well, updated php-curl packages are
available that provide a new curl PHP module compiled against the fixed code.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:224
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the curl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"curl-7.12.1-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.12.1-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.12.1-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.13.1-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.13.1-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.13.1-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.14.0-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-7.14.0-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcurl3-devel-7.14.0-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-curl-5.0.4-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"curl-", release:"MDK10.1")
 || rpm_exists(rpm:"curl-", release:"MDK10.2")
 || rpm_exists(rpm:"curl-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4077", value:TRUE);
}
