#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Sebastian Krahmer
#
# This script is released under the GNU GPL v2


if(description)
{
 script_id(14313);
 script_bugtraq_id(10955);
 script_cve_id("CVE-2004-0778");
 script_version ("$Revision: 1.6 $");
 
 
 name["english"] = "CVS file existence information disclosure weakness";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number,
can be exploited by malicious users to gain knowledge of 
certain system information.

This behaviour can be exploited to determine the existence 
and permissions of arbitrary files and directories on a 
vulnerable system.


Solution : Upgrade to CVS 1.11.17 and 1.12.9, or newer

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nes", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

port = get_kb_item("Services/cvspserver");
if(!port) port = 2401;
if(!get_port_state(port)) exit(0);

version = get_kb_item(string("cvs/", port, "/version"));
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     		security_warning(port);
