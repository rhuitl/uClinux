#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
# 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10822);
 script_bugtraq_id(2698);
 script_version("$Revision: 1.8 $");
 
 name["english"] = "Multiple WarFTPd DoS";
 name["francais"] = "Dos WarFTPd multiple";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote WarFTPd server is running a 1.71 version.

It is possible for a remote user to cause a denial of
service on a host running Serv-U FTP Server, G6 FTP Server
or WarFTPd Server. Repeatedly submitting an 'a:/' GET or
RETR request, appended with arbitrary data,
will cause the CPU usage to spike to 100%.

Reference: http://www.securityfocus.com/bid/2698

Solution : upgrade to the latest version of WarFTPd
Risk factor : Medium";
                 
                 
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Checks if the version of the remote warftpd",
                francais:"Détermine la version du warftpd distant");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2000 StrongHoldNET",
                  francais:"Ce script est Copyright (C) 2000 StrongHoldNET");
                  
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

 if(("WarFTPd 1.71" >< banner))
   security_warning(port);

