# References:
# From: Stefan Esser <s.esser@e-matters.de>
# Subject: Advisory 01/2003: CVS remote vulnerability
# To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#   vulnwatch@vulnwatch.org
# Message-ID: <20030120212523.GA17993@php.net>
# Date: Mon, 20 Jan 2003 22:25:23 +0100
   
if(description)
{
 script_id(11385);
 script_bugtraq_id(6650);
 script_version ("$Revision: 1.12 $");
 
 script_cve_id("CVE-2003-0015");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:012-07");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:0007");

 
 name["english"] = "CVS pserver double free() bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number,
is vulnerable to a double free() bug which may allow an
attacker to gain a shell on this host.

Solution : Upgrade to CVS 1.11.5
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.[0-4][^0-9]).*", string:version))
     	security_hole(port);
