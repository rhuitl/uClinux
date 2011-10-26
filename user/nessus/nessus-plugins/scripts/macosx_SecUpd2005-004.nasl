#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18099);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0193");
 script_bugtraq_id (12334);
 name["english"] = "Mac OS X Security Update 2005-004";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-004. This security
update contains security fixes for the following application :

- iSync (local privilege escalation)

Solution : http://docs.info.apple.com/article.html?artnum=301326
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-004";
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
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-004", string:packages)) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.[0-9][0-9]\.)", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2005-0193", value:TRUE);
}
