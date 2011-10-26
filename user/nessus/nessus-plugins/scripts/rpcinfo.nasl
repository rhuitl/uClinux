# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(11111);
 script_version ("$Revision: 1.16 $");
 name["english"] = "rpcinfo -p";
 name["francais"] = "rpcinfo -p";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script calls the DUMP RPC on the port mapper, to obtain the
list of all registered programs.

Risk factor : None";


 desc["francais"] = "
Ce script appelle la RPC DUMP sur le portmapper, pour obtenir la 
liste de tous les programmes enregistrés.

Facteur de risque : Aucun";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Dumps all the registered RPC";
 summary["francais"] = "Affiche toutes les RPC enregistrées";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "RPC"; 
 family["francais"] = "RPC";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

#
include("misc_func.inc");

# If the portmapper is not installed, then just exit
portmap = get_kb_item("rpc/portmap");
if(!portmap)exit(0);


report_tcp = make_list();
report_udp = make_list();

soc = open_sock_tcp(portmap);
if (! soc) exit(0);

# RPC Names, from Linux /etc/rpc

rpc_names="
portmapper	100000	portmap sunrpc rpcbind
rstatd		100001	rstat rup perfmeter rstat_svc
rusersd		100002	rusers
nfs		100003	nfsprog
ypserv		100004	ypprog
mountd		100005	mount showmount
ypbind		100007
walld		100008	rwall shutdown
yppasswdd	100009	yppasswd
etherstatd	100010	etherstat
rquotad		100011	rquotaprog quota rquota
sprayd		100012	spray
3270_mapper	100013
rje_mapper	100014
selection_svc	100015	selnsvc
database_svc	100016
rexd		100017	rex
alis		100018
sched		100019
llockmgr	100020
nlockmgr	100021
x25.inr		100022
statmon		100023
status		100024
bootparam	100026
ypupdated	100028	ypupdate
keyserv		100029	keyserver
sunlink_mapper	100033
tfsd		100037
nsed		100038
nsemntd		100039
showfhd		100043	showfh
ioadmd		100055	rpc.ioadmd
NETlicense	100062
sunisamd	100065
debug_svc 	100066  dbsrv
ypxfrd		100069  rpc.ypxfrd
bugtraqd	100071
kerbd		100078
event		100101	na.event	# SunNet Manager
logger		100102	na.logger	# SunNet Manager
sync		100104	na.sync
hostperf	100107	na.hostperf
activity	100109	na.activity	# SunNet Manager
hostmem		100112	na.hostmem
sample		100113	na.sample
x25		100114	na.x25
ping		100115	na.ping
rpcnfs		100116	na.rpcnfs
hostif		100117	na.hostif
etherif		100118	na.etherif
iproutes	100120	na.iproutes
layers		100121	na.layers
snmp		100122	na.snmp snmp-cmc snmp-synoptics snmp-unisys snmp-utk
traffic		100123	na.traffic
nfs_acl		100227
sadmind		100232
nisd		100300	rpc.nisd
nispasswd	100303	rpc.nispasswdd
ufsd		100233	ufsd
pcnfsd		150001	pcnfs
amd		300019  amq
# Legato NetWorker
nsrd		390103	nsr	 # NetWorker service
nsrmmd		390104	nsrmm	 # NetWorker media mupltiplexor daemon
nsrindexd	390105	nsrindex # NetWorker file index daemon
nsrmmdbd	390107	nsrmmdb  # NetWorker media management database daemon
nsrjb		390110	nsrjbd	 # NetWorker jukebox-control service
nsrexec		390113	nsrexecd # NetWorker client execution service
nsrnotd		390400		 # NetWorker notary service
#
sgi_fam		391002	fam
netinfobind	200100001
bwnfsd		545580417
fypxfrd		600100069 freebsd-ypxfrd
";

i=0;

# A big thanks to Ethereal!

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack = 
raw_string(	0x80, 0, 0, 0x28,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Programm = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 4,		# Procedure = 4
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0	# Null verifier
	);

send(socket: soc, data: pack);

r = recv(socket: soc, length: 4, min: 4);
if(strlen(r) < 4)exit(0);

last_frag = r[0];
y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
#display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
# First 4 bytes are XID
r = recv(socket: soc, length: 4, min: 4);

# Reply?
r = recv(socket: soc, length: 4, min: 4);
y =ord(r[0])*256; y=y+ord(r[1]); y=y*256; y=y+ord(r[2]); y=y*256;y=y+ord(r[3]);

# Accepted?
r = recv(socket: soc, length: 4, min: 4);
a =ord(r[0])*256; a=a+ord(r[1]); a=a*256; a=a+ord(r[2]); a=a*256;a=a+ord(r[3]);

# Next 8 bytes are verifier
r = recv(socket: soc, length: 8, min: 8);

# Next four is execution status
r = recv(socket: soc, length: 4, min: 4);
z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);

#display("Reply=", y, "\nAccepted=", a,"\nExec=", z, "\n");

# Reply (1) && accepted (0) && executed successfully (0)
if ((y != 1) || (a != 0) || (z != 0))
{
  close(soc);
  exit(0);
}

# Value follow?
r = recv(socket: soc, length: 4, min: 4);
vf =ord(r[0])*256; vf=vf+ord(r[1]); vf=vf*256; vf=vf+ord(r[2]); vf=vf*256;vf=vf+ord(r[3]);
len = 28;
while (vf)
{
  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }
  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  program = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  version = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  proto = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  port = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len = len+4;
  z = ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  vf = z;

  # Running get_port_state is not a great idea: we miss some registered RPC.
  #if ((proto == 17 ) || get_port_state(port))
  {
    req = string("^[a-zA-Z0-9_-]+[ \t]+", program);
    str = egrep(string:rpc_names, pattern: req);
    name = ereg_replace(string: str, 
		pattern: string("^([a-zA-Z0-9_-]+)[ \t]+.*"),
		replace: "\1");
    alias =  ereg_replace(string: str, 
		pattern: string("^[a-zA-Z0-9_-]+[ \t]+[0-9]+[ \t]*(.*)[\r\n]+"),
		replace: "\1");
    #if (! name) name="";
    #if (! alias) alias = "";

    #display("program=", program, "\nname=", name, "\nalias=", alias, "version=", version,"\nproto=", proto, "\nport=", port, "\nvalue follow=", vf,"\n\n");

    m = string("RPC program #", program, " version ", version);
    if (name) m = string(m, " '", name, "'");
    if (alias) m = string(m, " (", alias, ")");
    m = string(m, " is running on this port");
    if (proto == 6)
    {
      report_tcp[port] += m + '\n';
      #security_note(port: port, data: m);
      # Remember service
      if ( port <= 65535 && port > 0 )
      {
       if (name) register_service(port: port, proto: string("RPC/", name));
       else      register_service(port: port, proto: string("RPC/", program));
      }
    }
    if (proto == 17) report_udp[port] += m + '\n'; 
    i=i+1;
  }
}

foreach port (keys(report_tcp))
{ 
 if ( port > 0 && port <= 65535 ) security_note(port:port, data:report_tcp[port]);
}

foreach port (keys(report_udp))
{ 
 if ( port > 0 && port <= 65535 ) security_note(port:port, data:report_udp[port], proto:"udp");
}


