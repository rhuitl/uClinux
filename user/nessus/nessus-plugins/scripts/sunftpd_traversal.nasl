#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11374);
 script_version ("$Revision: 1.6 $");
 #NO bugtraq_id
 script_cve_id("CVE-2001-0283");
 name["english"] = "SunFTP directory traversal";

 script_name(english:name["english"]);

 desc["english"] = "
Directory traversal vulnerability in SunFTP build 9 allows
remote attackers to read arbitrary files via .. (dot dot)
characters in various commands, including (1) GET, (2) MKDIR,
(3) RMDIR, (4) RENAME, or (5) PUT.

Solution : Switching to another FTP server, SunFTP is discontinued.


Risk factor : High";


 script_description(english:desc["english"]);


 script_summary(english:"Checks if the remote SunFTP has directory traversal vulnerability");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");


 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
 		  francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login"); 
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  if("SunFTP b9"><banner) {
    desc = "
Buffer overflow in SunFTP build 9(1) allows remote attackers to cause
a denial of service or possibly execute arbitrary commands by sending
more than 2100 characters to the server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Switching to another FTP server, SunFTP is discontinued.


Risk factor : High";

  security_hole(port:port, data:desc);
  }
 }

 exit(0);
}


login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
	#dir name may already exists, try 5 times to get one unused
	for(i=0;i<5;i++) {
		dir=crap(i+10);
		mkdir=string("MKD ../", dir, "\r\n");
		cwd=string("CWD ", dir, "\r\n");
		rmd=string("RMD ../", dir, "\r\n");
		up=string("CWD ..\r\n");

		#Try to creat a new dir
		send(socket:soc, data:mkdir);
		b = ftp_recv_line(socket:soc);
		if(egrep(pattern:"^257 .*", string:b)) {

			#If the system is not vulnerable, it may create the
			#new dir in the current dir, instead of the parent dir.
			#if we can CWD into it, the system is not vunerable.
			
			send(socket:soc, data:cwd);
			b = ftp_recv_line(socket:soc);
			if(!egrep(pattern:"^250 .*", string:b)) {
				security_hole(port);
			} else {
				send(socket:soc, data:up);	#cd..
			}
			send(socket:soc, data:rmd);
			break;
		}
	}

	ftp_close(socket:soc);

  }

}
