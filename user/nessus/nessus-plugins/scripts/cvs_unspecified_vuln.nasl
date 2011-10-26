#
# (C) Tenable Network Security 
#
if(description)
{
 script_id(18097);
 script_bugtraq_id(13217);
 script_version ("$Revision: 1.4 $");
 
 script_cve_id("CVE-2005-0753");
 name["english"] = "CVS Multiple Unspecified Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number,
is vulnerable to a double free() bug which may allow an
attacker to gain a shell on this host.

Solution : Upgrade to CVS 1.12.12 or 1.11.20
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("cvs_double_free.nasl");
 exit(0);
}

include('global_settings.inc');
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

version = get_kb_item(string("cvs/", port, "/version"));

if (  ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-9][^0-9])|12\.([0-9][^0-9]|1[0-1][^0-9])).*", string:version)) security_hole(port);
