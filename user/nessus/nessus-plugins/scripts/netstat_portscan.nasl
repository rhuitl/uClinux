#TRUSTED 191e6fa5edbe9dba8b6208506bb6ab5b4ec3c37eb3fe1c693e76fc29827ae6ee41e8f70b73d48f9909504fcce3e76e9c1716665b81f645deeb1d3ccfb32e5dde72468f0cdd2a6d7404fe6a66f8283825e8c750677947e4416fec29b0178e8a4432cf81065ca8b2dd6179683b1726a9b439dd5facd7a0875b2ebaf2693817d020e402f52749f2cb3ed723ca98777bb68ae225b5020713a11ec04ba38b1306e67c0d3af6f76d6a4fb505cea5854af560f9bb585a09fbfdc5037c97652cc78b132a183cce375e313bd0cda89ad1ccf1bc00535aa98f83fa232b3fe6617c07f3c30ad0fe77b1f6d63a14b1ccc619233f331b213be7a09723d25b81280f97688087d1afd99ba96467129f696ed5743ced87f266e7f69608af0f3c7831b2117f91c351160dfe4e36fb4496a25d170d074c5f5ae293e4bbff3504db8ad05d389710c024e84d6a249ef341ac951e056aff8352bc162d54fc95f55b76a2247b79ba25a047547d9073aa69c5f7582139a50b7d393098b6543465f9068a28b8bb9e86588ece32219ade1905bc7fdca92b37aed59d7c287adbf8b321cb70760fecc719f15ab559df48b54f61f98b07b4db892517c17d1d22dda12343f4c5db87eeef7fa8695a58be353113b8c36185f68ee506921a0f150d4d206a99f932535a50ba35d87c13ccfc5e9ec5ddc119c2427ff921c43e4e7726bc57bbcd9f7bc9a59917a953ce6d
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if ( ! defined_func("pread") ) exit(0);



if(description)
{
 script_id(14272);
 script_version ("1.9");
 name["english"] = "Netstat 'scanner'";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs netstat on the remote machine to find open ports.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find open ports with netstat";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Port scanners";
 family["francais"] = "Scanners de ports";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("ping_host.nasl", "ssh_settings.nasl");
 exit(0);
}

#
include("ssh_func.inc");

buf = "";

# On the local machine, just run the command
if (islocalhost())
  buf = pread(cmd: "netstat", argv: make_list("netstat", "-a", "-n"));
else
{
# First try the netstat service, just in case
 s = open_sock_tcp(15);
 if (s)
 {
   while (r = recv(socket: s, length: 4096))
     buf += r;
   close(s);
 }
# Then try SSH if the result is not OK
 if ("LISTEN" >!< buf)
 {
 sock = ssh_login_or_reuse_connection();
 if (! sock)  exit(0);

 buf = ssh_cmd(socket:sock, cmd:"cmd /c netstat -an", timeout:60);

 if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
 {
 buf = ssh_cmd(socket:sock, cmd:"netstat -a -n", timeout:60);
 ssh_close_connection();
 if (! buf) { display("could not send command\n"); exit(0); }
 }
}
}

# display(buf);
ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;
check = 
 (! safe_checks()) ||
 ("yes" >< get_kb_item("global_settings/experimental_scripts_tests")) ||
 ("yes" >< get_preference("unscanned_closed")) ||
 ("yes" >< get_kb_item("global_settings/thorough_tests"));
# ("Avoid false alarms" >< get_kb_item("global_settings/report_paranoia"))

identd_n = 0; identd_err = 0;

foreach line (lines)
{
  # Windows
  v = eregmatch(pattern: '^[ \t]+(TCP|UDP)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)[ \t]+(0\\.0\\.0\\.0:0|\\*\\.\\*)[ \t]+', string: line, icase: 0);
  # Unix
  if (isnull(v))
   v = eregmatch(pattern: '^(tcp|udp)[46]?[ \t]+.*[ \t]+(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)[:.]([0-9]+)[ \t]+(.*[ \t]+LISTEN|0\\.0\\.0\\.0:\\*)', string: line, icase: 1);
  if (isnull(v))
  # tcp 0 0 :::22   :::*    LISTEN
  # tcp 0 0 ::1:25  :::*    LISTEN (1 = localhost)
  v = eregmatch(pattern: '^(tcp|udp)[ \t]+.*[ \t]+(:::)([0-9]+)[ \t]+.*[ \t]+LISTEN', string: line, icase: 1);

  # Solaris 9
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
      else
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);
      
      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = eregmatch(pattern: '^(TCP|UDP): +IPv4[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }
  

  if (!isnull(v))
  {
    if (check && defined_func("get_source_port"))
      identd_soc = open_sock_tcp(113);
    proto = tolower(v[1]);
    addr = v[2];
    port = v[3];
    # display("> ", addr, ":", port, " (", proto, ")\n");
    if (port < 1 || port > 65535)
     display('netstat_portscan(', get_host_ip(), '): invalid port number ', port, '\n');
    else if ((check && addr != "127.0.0.1") || 
        addr == "0.0.0.0" || addr == ip || addr == ":::" || addr == '*')
    {
      if (check && proto == "tcp")
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          scanner_add_port(proto: proto, port: port);
	  if (identd_soc)
	  {
	    req = strcat(port, ',', get_source_port(soc), '\r\n');
	    if (send(socket: identd_soc, data: req) <= 0)
	    {
	      # Let's be quick: do not reopen the socket if an error occurs
	      # Another plugin with complete the job
	      close(identd_soc);
	      identd_soc = NULL;
	      identd_err ++;
	      id = NULL;
	    }
	    else
	      id = recv_line(socket: identd_soc, length: 1024);
	    if (id)
	    {
	      ids = split(id, sep: ':');
	      if ("USERID" >< ids[1])
              {
		identd_n ++;
		set_kb_item(name: "Ident/tcp/"+port, value: ids[3]);
		security_note(port: port, 
data: 'identd reveals that this service is running as user '+ids[3]);
	      }
	    }
	  }
          close(soc);
        }
      }
      else
      scanner_add_port(proto: proto, port: port);
      # display(proto, "\t", port, "\n");
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (identd_soc) close(identd_soc);

if (scanned)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/udp_scanned", value: TRUE);
 set_kb_item(name: "Host/full_scan", value: TRUE);
 set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
 if (identd_n && ! identd_err)
   set_kb_item(name: "Host/ident_scanned", value: TRUE);
}

scanner_status(current: n, total: n);
exit(0);
