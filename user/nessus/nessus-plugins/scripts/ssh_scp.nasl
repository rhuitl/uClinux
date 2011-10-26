#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(11339);
 script_bugtraq_id(1742);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2000-0992");
 
 name["english"] = "scp File Create/Overwrite";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH 1.2.3, or 1.2. 
 
This version has directory traversal vulnerability in scp, it allows
a remote malicious scp server to overwrite arbitrary files via a .. (dot dot) attack.

Solution :
Patch and New version are available from SSH/OpenSSH.

Risk factor : Medium";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
		francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#
include("backport.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);

#Looking for OpenSSH product version number 1.2 and 1.2.3	
if(ereg(pattern:".*openssh[-_](1\.2($|\.3|[^0-9])).*",string:banner, icase:TRUE))security_warning(port);

if(ereg(pattern:".*ssh-.*-1\.2\.(1[0-4]|2[0-7])[^0-9]", string:banner, icase:TRUE))security_warning(port);
