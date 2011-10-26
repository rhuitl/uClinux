#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# This is a generic test which checks for FTP traversal vulns.
#

 desc = string("
The remote FTP server allows any anonymous user to browse the 
entire remote disk by issuing commands like :

	LIST ../../../../../
	LIST ..\\..\\..\\..\\..

Solution : Contact your vendor for a patch
Risk factor : High");



if(description)
{
 script_id(11112);
 script_bugtraq_id(2618, 2786, 5168, 11159);
 script_cve_id("CVE-2001-0680", "CVE-2001-1335", "CVE-2001-0582");
 script_version ("$Revision: 1.24 $");
 
 name["english"] = "Generic FTP traversal";
 
 script_name(english:name["english"]);
 script_description(english:desc);
 
 summary["english"] = "Attempts to get the listing of the remote root dir";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


function dir(loc, soc)
{
 local_var p;
 p = ftp_pasv(socket:soc);
 if(!p)exit(0);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(!soc2)return;
 
 #display("Ok\n");
 ls = strcat("LIST ", loc, '\r\n');
 send(socket:soc, data:ls);
 r = recv_line(socket:soc, length:4096);
 if(ereg(pattern:"^150 ", string:r))
 {
  result = ftp_recv_listing(socket:soc2);
  close(soc2);
  r = ftp_recv_line(socket:soc);
  return(result);
 }
 close(soc2);
 return;
}


#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", get_host_name())))
 {
  l1 = dir(loc: "/", soc: soc);	# previous version used "/"
  if (isnull(l1))
    l1 = dir(loc: "/", soc: soc);
  if (isnull(l1))
	 {
    ftp_close(socket: soc);
	  exit(0);
	 } 
  patterns = 
   make_list(	"../../../../../../../", 
		"..\..\..\..\..\..\..\",
		"..%5c..%5c..%5c..%5c..%5c..%5c..%5c",
		"\..\..\..\..\..\",	# platinum FTP 1.0.7
		"...",
		"/...",
		"/......",
		"\...",
		"...\",
		"..../",
		"\",
		"/");
  foreach pat (patterns)
  {
    l2 = dir(loc: pat, soc: soc);
    
    # ncftpd workaround
    if (strlen(l2) &&
        ! match(string: l2, pattern: "*permission denied*", icase: TRUE) &&
        ! match(string: l2, pattern: "*no such file or directory*", icase: TRUE) &&
	! match(string: l2, pattern: "*total 0*", icase: TRUE) &&
        l1 != l2)
  {
       #display(l1, "\n****\n"); display(l2, "\n");
       report = string(desc, "\n\n", "The command we found to escape the chrooted environment is : ", pat, "\nThe root dir of the remote server contains :\n", l2);
	  security_hole(port:port, data:report);
       ftp_close(socket: soc);
	  exit(0);
  }	 
	  
  }	 
 }
  ftp_close(socket: soc);
}

