#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11105);
 script_bugtraq_id(3343);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0960");
 name["english"] = "ARCserve hidden share";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Backup share can be accessed without authentication.

Description :

The remote host has an accessible ARCSERVE$ share.

Several versions of ARCserve store the backup agent user name
and password in cleartext in this share. 

An attacker may use this flaw to obtain the password file of 
the remote backup agent, and use it to gain more privileges 
on this host.

Solution :

Limit access to this share to the backup account and domain
administrator.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to ARCSERVE$";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include ("smb_func.inc");

port = kb_smb_transport();
if(!port) port = 139;

name = kb_smb_name();
if(!name)exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:NULL, password:NULL, domain:NULL, share:"ARCSERVE$");
if ( r != 1 ) 
{
 exit(1);
}

# Open current directory in read mode
handle = CreateFile (file:"", desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull (handle) )
{
 CloseFile(handle:handle);
 security_hole (port);
}

NetUseDel ();
