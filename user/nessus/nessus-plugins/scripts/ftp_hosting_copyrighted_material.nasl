#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11779);
 script_version ("$Revision: 1.11 $");

 script_name(english:"FTP server hosting copyrighted material");
	     
 script_description(english:"
This script determines if the remote FTP server hosts
potentially copyright-infringing files, such as mp3, wav,
avi or asf files.");
 
 script_summary(english:"Checks if the remote ftp server hosts mp3/wav/asf/mpg files");

 script_category(ACT_GATHER_INFO);
 script_family(english:"Peer-To-Peer File Sharing");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service_3digits.nasl", "logins.nasl", "smtp_settings.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

function get_files(socket, basedir, level)
{
 local_var r,p,s,l,k,sl,m;
 
 send(socket:socket, data:'CWD ' + basedir + '\r\n');
 r = ftp_recv_line(socket:socket);
 if(!egrep(pattern:"^250 ", string:r))return NULL;
 
 
 if( level > 3 )
 	return NULL;
	
 p = ftp_pasv(socket:socket);
 if(!p)return NULL;
 
 s = open_sock_tcp(p, transport:get_port_transport(port));
 if(!s)return NULL;
 send(socket:socket, data:'NLST .\r\n' );
 r = ftp_recv_line(socket:socket);
 if ( egrep(string:r, pattern:"^150 ") )
 {
 l = ftp_recv_listing(socket:s);
 r = ftp_recv_line(socket:socket);
 }
 close(s);
 l = split(l, keep:0);
 m = make_list();
 foreach k (l)
 {
  m = make_list(m, basedir + k);
 }
 
 foreach k (l)
 {
  sl = get_files(socket:soc, basedir:basedir + k + '/', level:level + 1);
  if( !isnull(sl) )
  	m = make_list(m, sl);
 }
 return m;
}

if(!login)
{
 login = "anonymous";
 domain = get_kb_item("Settings/third_party_domain");
 pass  = string("nessus@", domain);
}

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
report = NULL;
if(soc)
{
 r = ftp_authenticate(socket:soc, user:login, pass:pass);
 if(r)
 {
  files = get_files(socket:soc, basedir:"/", level:0);
  num_suspects = 0;
  foreach file (files)
  {
   if(ereg(pattern:".*\.(mp3|mpg|mpeg|ogg|avi|wav|asf|wma)", string:file, icase:TRUE))
   {
    report += ' - ' + file + '\n';
    num_suspects ++;
    if( num_suspects > 40 )
    {
      report += ' - ... (more) ...\n';
      break;
    }
   }
  }
 }
 close(soc);
}

if( report != NULL )
{
 report = '
Here is a list of files which have been found on the remote FTP server.
Some of these files may contain copyrighted materials, such as commercial
movies or music files. 

If any of this file actually contains copyrighted material and if
they are freely swapped around, your organization might be held liable
for copyright infringement by associations such as the RIAA or the MPAA.

' + report + '

Solution : Delete all the copyrighted files';

 security_warning(port:port, data:report);
}


