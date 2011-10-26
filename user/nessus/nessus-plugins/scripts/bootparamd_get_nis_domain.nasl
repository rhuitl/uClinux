if(description)
{
 script_id(12237);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Obtain the NIS domain name using bootparamd";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to obtain the remote NIS domain name 
if the remote host is running bootparamd.

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the presence of a RPC service";
 summary["francais"] = "vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Renaud Deraison");
 family["english"] = "NIS"; 
 family["francais"] = "NIS";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

include("misc_func.inc");


function getpad(f)
{
 f = f % 255;
 if(f < 0x7F)
  return(raw_string(0x00, 0x00, 0x00, f));
 else
  return(raw_string(0xFF, 0xFF, 0xFF, f));
}

function extract_name(data)
{
 clt_len = ord(data[27]);
 nam = "";
 for(_i = 0; _i < clt_len ; _i = _i + 1)
 {
  nam = string(nam, data[28+_i]);
 }
 return(nam);
}

function extract_domain(data)
{
 clt_len = ord(data[27]);
 align = 4 - clt_len%4;
 if(align == 4)align = 0;
 
 
 dom_len = ord(data[27+clt_len+align+4]);
 dom = "";
 for(_i=0;_i<dom_len;_i=_i+1)
 {
  dom = string(dom, data[27+clt_len+align+5+_i]);
 }
 return(dom);
}


nis_dom = "";

RPC_PROG = 100026;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port)exit(0);


ip = split(get_host_ip(), sep:".", keep:FALSE);
ip_a = int(ip[0]);
ip_b = int(ip[1]);
ip_c = int(ip[2]);
ip_d = int(ip[3]);

pada = getpad(f:ip_a);
padb = getpad(f:ip_b);
padc = getpad(f:ip_c);
res = NULL;
soc = open_sock_udp(port);


for(ip_d = 1; ip_d < 254; ip_d ++ )
{    
 padd = getpad(f:ip_d);
 req = raw_string(rand()%256, rand()%256, rand()%256, rand()%256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xBA, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01) + pada + padb + padc + padd;
 send(socket:soc, data:req);
}

ip_d = int(ip[3]);
r = recv(socket:soc, length:4096);
if ( r )
{
  	name =  extract_name(data:r);
	domain = extract_domain(data:r);
	res = res + string(ip_a, ".", ip_b, ".", ip_c,".", ip_d , " - ", name, " - NIS domain : ", domain, "\n");
}

close(soc);

if(strlen(res))
{
 report = 
'Using the remote bootparamd service, it was possible to obtain
the NIS domain of the network :\n' + res +
'Solution : Filter incoming traffic to this port';
 security_note(proto:"udp", port:port, data:report);
 if( domain )set_kb_item(name:"RPC/NIS/domain", value:domain);
}
