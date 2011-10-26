#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# ssh_recv() function and the idea to display the 
# SSH key fingerprint are thanks to discussion with 
# Nicolas Pouvesle

if(description)
{
 script_id(10881);
#script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.16 $");

 
 name["english"] = "SSH protocol versions supported";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin determines which versions of the SSH protocol
the remote SSH daemon supports

Risk factor : None";



 script_description(english:desc["english"]);
 
 summary["english"] = "Negotiate SSHd connections";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 family["english"] = "General";

 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("misc_func.inc");

function test_version(version)
{
soc = open_sock_tcp(port);
if(!soc) exit(0);
r = recv_line(socket:soc, length:255);
if(!r) exit(0);
if(!ereg(pattern:"^SSH-.*", string:r)){
	close(soc);
	return(0);
	}

str = string("SSH-", version, "-NessusSSH_1.0\n");
send(socket:soc, data:str);
r = recv_line(socket:soc, length:250);
close(soc);
if(!strlen(r))return(0);
if(ereg(pattern:"^Protocol.*version", string:r))return(0);
else return(1);
}





function ssh_recv(socket)
{
 local_var len, head, data;

 head  = recv(socket:socket, length:4, min:4);
 if ( strlen(head) < 4 ) return NULL;

 len = ord(head[2]) * 256 + ord(head[3]);
 data = recv(socket:socket, length:len, min:len);
 return head + data;
} 

function ssh2_get_fingerprint(port)
{
 local_var soc,key, key_len, key_len_str, blob, fingerprint, fg, i;
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 buf = recv_line(socket:soc, length:4096);
 send(socket:soc, data:'SSH-2.0-Nessus\n');

 key = ssh_recv(socket:soc);

 if ( "Protocol" >!< key && key != NULL )
 {
  send(socket:soc, data:key);
  send(socket:soc, data:raw_string(0,0,0,0x14,6,0x22,0,0,4,0,0,0,4,0,0,0,0x20,0,0,0,0,0,0,0));
  blob = ssh_recv(socket:soc);

  send(socket:soc, data:hex2raw(s:"0000008c0620000000806e6129d1aae5d13d7215634527390d92cfe5e595528e9479c9a070b8bae1c58ba1e0d3c441afd652c031875d3cb4050fe79e4cd46c66205c64059992f7865816fe516dffcde4a88216ea2d0588ee6c0795be3032110c00c2948d3c35b884198d38e0806d4c2689937b9591ef286f3be73986e4ee073d75d0ea92e0fe4d1d9d5b000000000000"));

  blob = ssh_recv(socket:soc);
  close(soc);
  if ( ! blob ) return NULL;
  key_len_str = substr(blob, 6, 9);
  key_len = ord(key_len_str[2]) * 256 + ord(key_len_str[3]);
  key = substr(blob, 10, 10 + key_len - 1);
  fingerprint = hexstr(MD5(key));
  fg = "";
  for ( i = 0 ; i < strlen(fingerprint) ; i += 2 )
  {
   fg += substr(fingerprint, i, i + 1);
   if ( i + 2 < strlen(fingerprint) ) fg += ":";
  }

  return fg;
 }
 return NULL;
}

function ssh1_get_fingerprint(port)
{
 local_var soc,key, key_len, key_len_str, blob, fingerprint, fg, i;
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 buf = recv_line(socket:soc, length:4096);
 send(socket:soc, data:'SSH-1.5-Nessus\n');

  blob = ssh_recv(socket:soc);
  close(soc);
  if ( blob != NULL && "Protocol" >!< blob )
  {
  idx = stridx(hexstr(blob), "e8dc4c7f1b53b99ff6f89bc7bf0448cf587d667");
  key_len_str = substr(blob, 130,131  );
  key_len = ord(key_len_str[0]) * 256 + ord(key_len_str[1]);
  key = substr(blob, 132, 132 + 127 ) + raw_string(0x23);
  fingerprint = hexstr(MD5(key));
  fg = "";
  for ( i = 0 ; i < strlen(fingerprint) ; i += 2 )
  {
   fg += substr(fingerprint, i, i + 1);
   if ( i + 2 < strlen(fingerprint) ) fg += ":";
  }
  return fg;
 }
 return NULL;
}
port = 22;



port = get_kb_item("Services/ssh");
if(!port)port = 22;


if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

v = 0;

vers_1_33 = 0;
vers_1_5  = 0;
vers_1_99 = 0;
vers_2_0  = 0;

# Some SSHd implementations reply to anything.
if(test_version(version:"9.9"))
	{
	exit(0);
	}

if(test_version(version:"1.33"))
	{
	v = 1;
	vers_1_33 = 1;
	}
	
if(test_version(version:"1.5"))
	{
	v = 1;
	vers_1_5 = 1;
	}
	
if(test_version(version:"1.99"))
	{
	v = 1;
	vers_1_99 = 1;
	}

if(test_version(version:"2.0"))
	{
	v = 1;
	vers_2_0 = 1;
	}



report = string("The remote SSH daemon supports the following versions of the\n",
"SSH protocol :\n\n");

if(vers_1_33)report = string(report, "  . 1.33\n");
if(vers_1_5){
	report = string(report, "  . 1.5\n");
	fg1 = ssh1_get_fingerprint(port:port);
	}
if(vers_1_99)report = string(report, "  . 1.99\n");
if(vers_2_0) {
	report = string(report, "  . 2.0\n");
	fg2 = ssh2_get_fingerprint(port:port);
	}


if ( fg1 || fg2 ) report += '\n\n';
if ( fg1 ) report += "SSHv1 host key fingerprint : " + fg1 + '\n';
if ( fg2 ) report += "SSHv2 host key fingerprint : " + fg2 + '\n';

if(v)security_note(port:port, data:report);
