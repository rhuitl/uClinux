#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  Tenable Network Security
#
# ref: Subversion team September 2004
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14800);
 script_version ("$Revision: 1.4 $");

 script_bugtraq_id(11243);
 script_cve_id("CVE-2004-0749");
 script_xref(name:"OSVDB", value:"10217");

 name["english"] = "Subversion Module unreadeable path information disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
You are running a version of Subversion which is older than 1.0.8 or
1.1.0-rc4. 

A flaw exist in older version, in the apache module mod_authz_svn,
which fails to properly restrict access to metadata within unreadable
paths. 

An attacker can read metadata in unreadable paths, which can contain
sensitive information such as logs and paths. 

Solution : Upgrade to subversion 1.0.8, 1.1.0-rc4 or newer 
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

if (egrep(string:r, pattern:".*subversion-1\.(0\.[0-7][^0-9]|1\.0-rc[1-3][^0-9]).*"))
{
	security_warning(port);
}

close(soc);
exit(0);
