#  
# (C) Tenable Network Security
#
if(description)
{
 script_id(11947);
 script_bugtraq_id(9178);
 script_version ("$Revision: 1.8 $");
 if ( defined_func("script_xref") ) script_xref(name:"MDKSA", value:"MDKSA-2003:112-1");
 
 
 name["english"] = "CVS pserver dir create bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number, may allow
an attacker to create directories and possibly files at the root
of the filesystem holding the CVS repository.

Solution : Upgrade to CVS 1.11.10
Risk factor : Medium";


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
version =  get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);

if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.[0-9][^0-9]).*", string:version))
     	security_warning(port);
