#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11768);
 script_bugtraq_id(7974);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "proftpd mod_sql injection";

 
 script_name(english:name["english"]);
             
 desc["english"] = "
The remote FTP server is vulnerable to a SQL injection when
it processes the USER command.

An attacker may exploit this flaw to log into the remote host
as any user.

Solution : If the remote server is ProFTPd, upgrade to ProFTPD 1.2.10 when
available, or switch the SQL backend to PostgreSQL.

Risk factor : High";
                 
                 
                     
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Performs a SQL insertion");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
                  
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

soc = open_sock_tcp(port);
if(!soc)exit(0);

banner = ftp_recv_line(socket:soc);
if ( ! egrep(pattern:"^220 ", string:banner) ) exit(0);

if(!banner)exit(0);
send(socket:soc, data:'USER "\r\n');
r = recv_line(socket:soc, length:4096);
if(!r)exit(0);
close(soc);



soc = open_sock_tcp(port);
if(!soc)exit(0);
# The following causes a syntax error and makes the FTP
# daemon close the session
banner = ftp_recv_line(socket:soc);
if(!banner)exit(0);
send(socket:soc, data:string("USER '\r\n"));
r = recv_line(socket:soc, length:4096);
if(!r){ security_hole(port); }
close(soc);
