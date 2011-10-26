#  
# (C) Tenable Network Security
#
if(description)
{
 script_id(12212);
 script_bugtraq_id(10140);
 script_version ("$Revision: 1.6 $");
 
 
 name["english"] = "CVS server piped checkout access validation";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number, might allow
an attacker to checkout RCS archive files that are outside of the 
cvs root.

Solution : Upgrade to CVS 1.11.15 or 1.12.7
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-4])|12\.[0-6][^0-9]).*", string:version))
     	security_warning(port);
