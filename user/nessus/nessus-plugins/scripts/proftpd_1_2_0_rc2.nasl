#
# This script was written by Renaud Deraison <deraison@nessus.org>
# 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11407);
 script_bugtraq_id(6781);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2001-0318");
 
 name["english"] = "proftpd 1.2.0rc2 format string vuln";

 
 script_name(english:name["english"]);
             
 desc["english"] = "
The remote ProFTPd server is as old or older than 1.2.0rc2

There is a very hard to exploit format string vulnerability in
this version, which may allow an attacker to execute arbitrary
code on this host.

The vulnerability is believed to be nearly impossible to exploit
though

Solution : Upgrade to a newer version
Risk factor : Medium";
                 
                 
                     
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Checks if the version of the remote proftpd",
                francais:"Détermine la version du proftpd distant");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);

if(egrep(pattern:"^220 ProFTPD 1\.[0-1]\..*", string:banner))security_warning(port);
else if(egrep(pattern:"^220 ProFTPD 1\.2\.0(pre.*|rc[1-2][^0-9])", string:banner))security_warning(port);
