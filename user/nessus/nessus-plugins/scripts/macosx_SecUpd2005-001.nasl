#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16251);
 script_version ("$Revision: 1.6 $");
 if (NASL_LEVEL >= 2191) script_cve_id("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", "CVE-2004-1036");
 script_bugtraq_id(12367, 12366, 12297, 11857);
 name["english"] = "Mac OS X Security Update 2005-001";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-001. This security
update contains a number of enhancements for the following programs :

- at commands
- ColorSync
- libxml2
- Mail
- PHP
- Safari
- SquirrelMail

Solution : http://docs.info.apple.com/article.html?artnum=300770
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-001";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.7 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.7\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2005-001", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([8-9]\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 list = make_list("CVE-2005-0125", "CVE-2005-0126", "CVE-2004-0989", "CVE-2005-0127", "CVE-2003-0860", "CVE-2003-0863", "CVE-2004-0594", "CVE-2004-0595", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065", "CVE-2004-1314", "CVE-2004-1036");
 foreach cve (list) set_kb_item(name:cve, value:TRUE);
}
