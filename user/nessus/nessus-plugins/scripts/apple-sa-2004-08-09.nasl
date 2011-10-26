#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# This script is released under the GNU GPLv2


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14251);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_bugtraq_id(8945);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"7098");
 script_cve_id("CVE-2003-1011");
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Apple SA 2003-12-19";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2003-12-19.

Mac OS X contains a flaw that may allow a malicious user 
with physical access to gain root access. 

The issue is triggered when the Ctrl and c keys are pressed 
on the connected USB keyboard during boot and thus interrupting 
the system initialization. 

It is possible that the flaw may allow root access resulting 
in a loss of integrity.

Solution : http://docs.info.apple.com/article.html?artnum=61798

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2003-12-19";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2003-12-19", string:packages) ) 
  {
	security_hole(0);
  }
  else
  {
  	#all can fixes with this security updates
	#set_kb_item(name:"CVE-2003-1007", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1006", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1009", value:TRUE);
  	#set_kb_item(name:"CVE-2003-0792", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1010", value:TRUE);
  	#set_kb_item(name:"CVE-2003-0962", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1005", value:TRUE);
  	#set_kb_item(name:"CVE-2003-1008", value:TRUE);
	set_kb_item(name:"CVE-2003-1011", value:TRUE);
  }
}
