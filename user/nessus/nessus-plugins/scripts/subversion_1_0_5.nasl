#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  Tenable Network Security
#
# ref: ned <nd@felinemenace.org>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(12284);
 script_bugtraq_id(10519);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0413");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"6935");
 if ( defined_func("script_xref") ) script_xref(name:"GLSA", value:"GLSA 200406-07");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2004:018");

 name["english"] = "Subversion SVN Protocol Parser Remote Integer Overflow";
 script_name(english:name["english"]);

 desc["english"] =
"A remote overflow exists in Subversion. svnserver fails to validate 
svn:// requests resulting in a heap overflow. With a specially 
crafted request, an attacker can cause arbitrary code execution 
resulting in a loss of integrity.

Solution : Upgrade to version 1.0.5 or newer 
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Subversion SVN Protocol Parser Remote Integer Overflow";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("subversion_detection.nasl");
 script_require_ports("Services/subversion");
 exit(0);
}



# start check
# mostly horked from MetaSploit Framework subversion overflow check

port = get_kb_item("Services/subversion");
if ( ! port ) port = 3690;

if (! get_tcp_port_state(port))
	exit(0);

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/nessusr0x ) ");

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);

if (! r)
	exit(0);

#display(r);

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*"))
{
	security_hole(port);
}

close(soc);
exit(0);
