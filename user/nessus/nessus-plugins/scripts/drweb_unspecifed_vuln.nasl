#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(14198);
 script_bugtraq_id(10628);
 script_version("$Revision: 1.2 $");

 name["english"] = "DrWeb Unspecified buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running DrWeb - an antivirus.

There is a buffer overflow in the remote version of Dr.Web which might
allow an attacker to execute arbitrary commands on the remote host. Very
little details are known regarding this issue at this time.

Solution : Upgrade to version 4.31.5 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Dr.Web";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("drweb_overflow.nasl");
 script_require_keys("DrWeb/Version");
 exit(0);
}


version = get_kb_item("DrWeb/Version");
if ( ! version ) exit(0);	
if(ereg(pattern:"([123]\..*|4\.([0-9][^0-9]|1[0-9]|2[0-9]|30|31\.[0-4]([^0-9]|$)))", string:version))
 	security_warning(port);
