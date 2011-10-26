#  
# (C) Tenable Network Security
#
if(description)
{
 script_id(11970);
 script_bugtraq_id(9306);
 script_version ("$Revision: 1.6 $");
 
 
 name["english"] = "CVS pserver CVSROOT passwd file cmd exec";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number, might allow
an attacker to execute arbitrary commands on the remote system as 
cvs does not drop root privileges properly.

Solution : Upgrade to CVS 1.11.11
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nes", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);
version = get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|10)).*", string:version))
     	security_hole(port);
