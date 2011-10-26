#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18521);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(13603);
 script_cve_id("CAN-2005-1579");
 name["english"] = "Quicktime < 7.0.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Mac OS X host is running a version of Quicktime 7 which is older
than Quicktime 7.0.1

The remote version of this software is vulnerable to an information disclosure
flaw when handling Quartz Composer files which may leak data to an arbitrary 
web location.

To exploit this flaw, an attacker would need to lure a user on the remote host 
into viewing a specially crafted Quartz Composer object. 

Solution : Install Quicktime 7.0.1
See also : http://www.securityfocus.com/advisories/8642
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Quicktime 7.0.1";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}




ver = get_kb_item("MacOSX/QuickTime/Version");
if ( ! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( version == "7.0.0" ) security_warning( port );
