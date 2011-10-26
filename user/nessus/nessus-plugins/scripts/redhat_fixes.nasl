#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12512);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0020");
 script_version ("$Revision: 1.5 $");
			
 name["english"] = "Red Hat Enterprise Linux fixes";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin writes in the knowledge base the CVE ids that we know
Red Hat enterprise Linux is not vulnerable to.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Fill the KB";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}


include("rpm.inc");


release = get_kb_item("Host/RedHat/release");
if ( ! release ) exit(0);
if ( egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:release) )
{
 set_kb_item(name:"CVE-2000-0666", value:TRUE);
 set_kb_item(name:"CVE-2003-0020", value:TRUE);
 set_kb_item(name:"CVE-2003-0192", value:TRUE);
 set_kb_item(name:"CVE-2003-0252", value:TRUE);
 set_kb_item(name:"CVE-2003-0682", value:TRUE);
 set_kb_item(name:"CVE-2003-0693", value:TRUE);
 set_kb_item(name:"CVE-2003-0695", value:TRUE);
}


if ( egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:release)) 
{
 set_kb_item(name:"CVE-2000-0666", value:TRUE);
 set_kb_item(name:"CVE-2003-0020", value:TRUE);
 set_kb_item(name:"CVE-2003-0192", value:TRUE);
}
