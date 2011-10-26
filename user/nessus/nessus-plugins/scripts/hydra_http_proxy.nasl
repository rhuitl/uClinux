#TRUSTED 5b1151fcc6a07bdc39ec126ed25238325c963ca113cb3b98706e15f18a8afa290fb9451f3c50f4845402da831fe7b4e4316eca67201e11eba44300cbb9f6118eed73b113371812d7645109657a30df8571c8fd3f374d53739b980f7145e97814c07d5bf6b0098367f07d87db85756bee69f892eb3fa9972a841f345101ba7ea56f9f25f32e3fe23998e6ea3a912b92e36442100397ce149e76f3ff410d8c62dd870f13490b6538be1a6cbb7a5da3296d45daf95804cf6d37655cf6ced7caea9c1d5e82e5e729652e2c8a73e72af63e70b71528126593f14c8dffda883182af1441e9f56513ee541782320393b518995a2040db08b75fff1b1937946819b1f10713886ce3a2809ad13618437de21c235dd9fd719058b1390a7a1c4d1b438ce7d88a72e4934c0696acbe90f014e37d81d5ae907eb11bf16310ea3e472356ae3dd2d75f29746a618b1312fa91a853c3dfeb684ce66fdc99577c96073b3513a5fd8142e375d016558b982f6a7d62a349182d9e73df32923e577de4da549e9eb4e7c2155bb098bd30aa56e975628a2688bce03e6601ee937098f3df461be0aa04a8484f5fa71f16b8c84bb70b26d1cfbc9147e9d4e848725a573bdbb95fc7f17ef0a666fdaac180056a3732fb552dfb5bc22fa29e098f5f86c551c8282d423529be1d677e058a6296a029549c9938d540b7a30d3460eee7ab7ad57bbe81526afa57e0
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15874);
 script_version ("1.2");
 name["english"] = "Hydra: HTTP proxy";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find HTTP proxy accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force HTTP proxy authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Web site (optional) :", value: "", type: "entry");

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/http_proxy", 3128);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/http_proxy");
if (! port) port = 3128;
if (! get_port_state(port)) exit(0);

# www.suse.com by default
opt = script_get_preference("Site (optional) :");
if (!opt) site = 'http://www.suse.com/';
else if (opt !~ '^(http|ftp)://') site = strcat('http://', opt);
else site = opt;
host = ereg_replace(string: site, pattern: '^(ftp|http://)([^/]+@)?([^/]+)/.*',
	replace: "\3");
if (host == site)
 req = 'GET '+site+' HTTP/1.0\r\n\r\n';
else
 req = 'GET '+site+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n';
s = open_sock_tcp(port);
if (!s) exit(0);
send(socket: s, data: req);
r = recv_line(socket: s, length: 1024);
close(s);
if (r =~ "^HTTP/1\.[01] +[234]0[0-9] ") exit(0);	# Proxy is not protected

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "http-proxy";

if (opt) argv[i++] = opt;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/http-proxy/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following accounts on the HTTP proxy:\n' + report);
