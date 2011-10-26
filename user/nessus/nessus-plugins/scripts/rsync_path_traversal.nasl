#
# This script is (C) 2003 Tenable Network Security
#
#

if (description)
{
 script_id(12230);
 script_bugtraq_id(10247);
 script_cve_id("CVE-2004-0426");
 
 script_version ("$Revision: 1.3 $");
 script_name(english:"rsync path traversal");
 desc["english"] = "
The remote rsync server might be vulnerable to a path traversal
issue.

An attacker may use this flaw to gain access to arbitrary files hosted
outside of a module directory.

Solution : Upgrade to rsync 2.6.1
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Remote file access");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}



port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);

welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 close(soc);
 if(!welcome)exit(0);
}


if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-7])[^0-9]", string:welcome))
{
 security_hole(port);
}
