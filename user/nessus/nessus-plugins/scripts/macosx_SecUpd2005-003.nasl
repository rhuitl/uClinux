#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17587);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(6347, 12478, 12863, 13224, 13220, 13226, 13237);
 #if (NASL_LEVEL >= 2200 )script_cve_id("CVE-2005-0340", "CVE-2005-0715", "CVE-2005-0716", "CVE-2005-0713", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015", "CVE-2004-1067", "CVE-2002-1347", "CVE-2004-0884", "CVE-2005-0712", "CVE-2005-0202", "CVE-2005-0235" );
 name["english"] = "Mac OS X Security Update 2005-003";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-003. This security
update contains security fixes for the following applications :

- AFP Server
- Bluetooth Setup Assistant
- Core Foundation
- Cyrus IMAP
- Cyrus SASL
- Folder Permissions
- Mailman
- Safari

Solution : http://docs.info.apple.com/article.html?artnum=301061
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-003";
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
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[78]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-003", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 foreach cve (make_list("CVE-2005-0340", "CVE-2005-0715", "CVE-2005-0716", "CVE-2005-0713", "CVE-2004-1011", "CVE-2004-1012", "CVE-2004-1013", "CVE-2004-1015", "CVE-2004-1067", "CVE-2002-1347", "CVE-2004-0884", "CVE-2005-0712", "CVE-2005-0202", "CVE-2005-0235" ))
	{
	set_kb_item(name:cve, value:TRUE);
	}
}
