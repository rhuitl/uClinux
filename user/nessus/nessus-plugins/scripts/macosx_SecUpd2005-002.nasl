#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17195);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0015");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1029");
 name["english"] = "Mac OS X Security Update 2005-002";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-002. This security
update contains a security bugfix for Java 1.4.2 :

A vulnerability in the Java Plug-in may allow an untrusted applet to 
escalate privileges, through JavaScript calling into Java code, including 
reading and writing files with the privileges of the user running the applet. 
Releases prior to Java 1.4.2 on Mac OS X are not affected by this 
vulnerability.

Solution : http://docs.info.apple.com/article.html?artnum=300980
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-002";
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
  if ( egrep(pattern:"^Java142\.pkg", string:packages) &&
      !egrep(pattern:"^SecUpd(Srvr)?2005-002", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.(9\.|[0-9][0-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2004-1029", value:TRUE);
}
