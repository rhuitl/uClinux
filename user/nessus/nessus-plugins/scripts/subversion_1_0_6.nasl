#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  Tenable Network Security
#
# ref: Subversion team July 2004
# This script is released under the GNU GPLv2

if(description)
{
 script_id(13848);
 script_cve_id("CVE-2004-1438");
 script_bugtraq_id(10800);
 script_version ("$Revision: 1.6 $");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8239");

 name["english"] = "Subversion Module File Restriction Bypass";
 script_name(english:name["english"]);

 desc["english"] = "
You are running a version of Subversion which is older than 1.0.6.

A flaw exist in older version, in the apache module mod_authz_svn.
An attacker can access to any file in a given subversion repository,
no matter what restrictions have been set by the administrator.

Solution : Upgrade to subversion 1.0.6 or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Check for Subversion version";
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

if (egrep(string:r, pattern:".*subversion-1\.0\.[0-5][^0-9].*"))
{
	security_warning(port);
}

close(soc);
exit(0);
