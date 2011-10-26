#
# (C) Tenable Network Security
#
 desc["english"] = "
Synopsis :

A distributed compiler is listening on the remote port.

Description :

The remote host is running distcc, a distributed GCC compiler.
distcc allows a user to use the resources several hosts to 
compile his programs more quickly.

As distcc allows anyone to execute arbitrary commands on the 
remote host, it should be configured to only accept connections 
from a restricted set of IP addresses, otherwise an attacker
can use it to obtain an interactive shell on the remote host,
with the privileges of the distcc daemon (usually 'distccd')

Solution :

Filter incoming traffic to this port, or use the '-a' option
switch to restrict the set of IP addresses distcc will accept.


See also :

http://distcc.samba.org/security.html

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

if(description)
{
 script_id(12638);
 script_version("$Revision: 1.9 $");
 
 name["english"] = "DistCC Detection";
 
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect the presence of DistCC";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 script_family(english:"Service detection");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

include("misc_func.inc");
include('global_settings.inc');

function __hex_value(num)
{
   if(num == "a")return(10);
   if(num == "b")return(11);
   if(num == "c")return(12);
   if(num == "d")return(13);
   if(num == "e")return(14);
   if(num == "f")return(15);
   return(int(num));
}


function hex2dec(xvalue)
{
 local_var ret, l, i, n, m;
  
 if(!xvalue)return(0);
 xvalue = tolower(xvalue);
 if ( '\r\n' >< xvalue )
        l = strlen(xvalue) - 2;
 else if ( '\n' >< xvalue)
        l = strlen(xvalue) - 1;
 else   l = strlen(xvalue);

 
 ret = 0;
 m = 1;
 if ( l == 0 ) return 0;
 
 # Remove the trailing spaces
 while(xvalue[l - 1]==" " && l > 0)l--;
 
 for(i=l;i>0;i--)
 {
  n = __hex_value(num:xvalue[i - 1]) * m;
  ret = ret + n;
  m = m * 16;
 }
 return int(ret);
}



argv = make_list("id",  "root", "#", "-c", "main.c", "-o", "main.o");
req  = "DIST00000001ARGC0000000" + max_index(argv);
n    = 0;
foreach arg (argv)
{
 req += "ARGV0000000" + strlen(arg) + arg;
}

req += 'DOTI00000001x\n';


if ( thorough_tests )
{
 port = get_unknown_svc(3632);
 if ( ! port ) exit(0);
}
else port = 3632;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
while ( TRUE )
{
 msg = recv(socket:soc, length:4);
 if ( ! msg ) exit(0);
 if ( msg == "DONE"  || msg == "STAT" ) msg += recv(socket:soc, length:8);
 else if ( msg == "SERR"  || msg == "SOUT" ) 
	{
	  msg_l = recv(socket:soc, length:8);
	  if ( strlen(msg_l) != 8 ) exit(0);
	  l = hex2dec(xvalue:msg_l);
	  data = recv(socket:soc, length:l);
	  if ( msg == "SOUT" && "uid=" >< data )
		{
		 report = desc["english"] + '\n\nPlugin output :\n\n' + 
			'It was possible to execute the command "id root", which produces :\n' + data;
		 register_service(port:port, proto:"distcc");
		 security_hole(port:port,data:report);
		 exit(0);
		}
	
	}
  else exit(0);
}
