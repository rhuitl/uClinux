if(description)
{
 script_id(12238);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Obtain the passwd NIS map";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script fetches the remote NIS 'passwd.byname' map, provided that
the NIS domain name could be obtained.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the presence of a RPC service";
 summary["francais"] = "vérifie la présence d'un service RPC";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Renaud Deraison");
 family["english"] = "NIS"; 
 family["francais"] = "NIS";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("bootparamd_get_nis_domain.nasl");
 script_require_keys("RPC/NIS/domain");
 exit(0);
}


include("misc_func.inc");

function pad(len)
{
 ret= "";
 for(_i = 0; _i < len ; _i = _i + 1)
 {
  ret = string(ret, raw_string(0));
 }
 return(ret);
}

function extract_key(data, tot)
{
 s = "";
  len_hi = ord(data[34+tcp+tot]);
  len_lo = ord(data[35+tcp+tot]);
  len = len_hi * 256;
  len = len + len_lo;
  s = "";
  for(i=0;i<len;i=i+1)
  {
   s = string(s, data[36+tcp+i+tot]);
  }
 return(s);
}

function extract_data(data)
{
 str = "";
 end =  strlen(data);
 tot = 0;
 flag = 1;
 f = 3;
 for(;flag;)
 {
  entry = extract_key(data:data, tot:tot);
  align = 4 - len % 4;
  if(align == 4)align = 0;
  tot = tot + i + align + 4;
  if((tot + 40) > strlen(data))flag = 0;
  if(f > 2)
  {
   if(strlen(entry))  str = string(str, entry, "\n");
  f = 1;
  }
  else f = f + 1;
 }
 return(str);
}

nis_dom = get_kb_item("RPC/NIS/domain");
if(!nis_dom)exit(0);

soc = 0;

RPC_PROG = 100004;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
if(port){
	tcp = 4;
	soc = open_priv_sock_tcp(dport:port);
	}

if(!soc)
{
 port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
 if ( ! port ) exit(0);
 tcp = 0;
 soc = open_priv_sock_udp(dport:port);
}

if(!soc)exit(0);


len = strlen(nis_dom);
x = len % 256;
y = len / 256;

align = 4 - len%4;
if(align == 4)align = 0;
pad = pad(len:align);
map = "passwd.byname";
len = strlen(map);
x2  = len % 256;
y2  = len / 256;
align = 4 - len%4;
if(align == 4)align = 0;
pad2 = pad(len:align);

req = raw_string(0xDE, 0xAD, 
	0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x86, 0xA4, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	y, x) + nis_dom + pad + raw_string(0x00, 0x00, y2, x2) +
	map + pad2;
	
tot_len = strlen(req);
tot_len_hi = tot_len / 256;
tot_len_lo = tot_len % 256;

if(tcp)req = raw_string(0x80, 0x00, tot_len_hi, tot_len_lo) + req;
send(socket:soc, data:req);
if ( tcp ) {
	 data = recv(socket:soc, length:4);
	 if ( ! data ) exit(0);
	 len = ord(data[2]) * 256 + ord(data[3]);
	}
else {
	data = NULL;
	len = 65535;
	}

data += recv(socket:soc, length:len);
if ( ! data ) exit(0);
mapcontent = extract_data(data:data);


if(strlen(mapcontent))
{
 report = string("It was possible to extract the map ", map, " using the NIS domain name ",
nis_dom, " :\n", mapcontent);
 
 if(tcp)security_hole(port:port, data:report);
 else security_hole(proto:"udp", port:port, data:report);
}
