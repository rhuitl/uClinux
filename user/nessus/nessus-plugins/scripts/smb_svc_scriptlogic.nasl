#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11562);
 script_bugtraq_id(7475, 7477);
 script_version ("$Revision: 1.4 $");

 name["english"] = "The ScriptLogic service is running";
 script_name(english:name["english"]);
 
 desc["english"] = "
The ScriptLogic service is running. 

There is a flaw in versions up to 4.05 of this service which may allow
an attacker to write arbitrary values in the remote registry with administrator
privileges, which can be used to gain a shell on this host.

*** Since Nessus was unable to determine the version of ScriptLogic
*** running on this host, this might be a false positive

Solution : Make sure you are running ScriptLogic 4.15 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of the ScriptLogic service";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows";
 family["francais"] = "Windows";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smb_enum_services.nasl");
 script_require_keys("SMB/svcs");
 exit(0);
}

#
# The script code starts here
#
port = get_kb_item("SMB/transport");
if(!port)port = 139;


services = get_kb_item("SMB/svcs");
if(services)
{
 if("[SLServer]" >< services)security_hole(port);
}
