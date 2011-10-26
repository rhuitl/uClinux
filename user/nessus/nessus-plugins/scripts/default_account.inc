#
# (C) Tenable Network Security
#
#
# Default Account
#
# This file implements (or will implement) various ways of determining if
# an account is valid
#
#
# $Id: default_account.inc,v 1.15 2006/05/05 12:55:31 mikhail Exp $
#

include('telnet_func.inc');
include('ssh_func.inc');


#
# Private functions
# 

function _check_telnet(port, login, password)
{
 local_var soc, res;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 res = telnet_negotiate(socket:soc);
 res += recv_until(socket:soc, pattern:"ogin:");
 if ( ! res ) exit(0);

 send(socket:soc, data:login + '\r\n');
 if ( isnull(password) )
  {
   send(socket:soc, data:'id\r\n');
   res = recv_until(socket:soc, pattern:"uid=");
   close(soc);
   if ( res ) return 1; 
   else return 0;
  }


 res = recv_until(socket:soc, pattern:"word:");
 if ( res == NULL ) 
 {
  close(soc);
  return 0;
 }

 send(socket:soc, data:password + '\r\n');
 send(socket:soc, data:'id\r\n');
 
 res = recv_until(socket:soc, pattern:"uid=");
 close(soc);
 if ( res ) return 1;
 else return 0;

}

#-------------------------------------------------------------------#


function check_account(login, password)
{
 local_var port, ret, banner, soc, res;
 

 if ( defined_func("bn_random") )
 {
  # Prefer login thru SSH rather than telnet
  port = get_kb_item("Services/ssh");
  if ( ! port ) port = 22;
  banner = get_kb_item("SSH/banner/" + port);
  # GoodTech SSH server does not respect SSH protocol ...
  if (banner && ("cryptlib" >!< banner)) 
  {
   soc = open_sock_tcp(port);
   if ( soc )
   {
   ret = ssh_login(socket:soc, login:login, password:password);
   close(soc);
   if ( ret == 0 ) return port;
   #else return 0; 
   }
  }
 }

 port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(get_port_state(port))
 {
  if ( isnull(password) ) password = "";
  res = _check_telnet(port:port, login:login, password:password);
  if(res)
   return(port);
 }
 return(0);
}
