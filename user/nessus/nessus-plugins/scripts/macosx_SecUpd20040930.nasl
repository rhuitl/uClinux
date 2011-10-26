#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15420);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0030");
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(11322, 11324, 11323);
 script_cve_id("CVE-2004-0921", "CVE-2004-0922", "CVE-2004-0558", "CVE-2004-0923", "CVE-2004-0924", "CVE-2004-0925", "CVE-2004-0926", "CVE-2004-0927");
 script_bugtraq_id(11207);
 name["english"] = "Mac OS X Security Update 2004-09-30";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-09-30. This security
update contains a number of enhancement for the following programs :

- AFP Server
- CUPS
- NetInfoManager
- postfix
- QuickTime
- ServerAdmin

These vulnerabilities may allow an attacker to cause a denial of service
of the remote service, to execute arbitrary code on the remote host
and to write to several files.

Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-09-30";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.5\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-30", string:packages) ) security_hole(0);
}
