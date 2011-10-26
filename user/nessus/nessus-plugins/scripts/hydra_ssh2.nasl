#TRUSTED 49c6a5d64cfc9129bddc63f40fcbfdb31014a2edcf91dc9d85711257b7dc6fec22083769582b0da0a78812526b9036f37a3dc8a04ead5453ee0d59eccd9427b76483daac852db260bff0e74f6ac66163263c5521110ac5b761ec7db505eebd9ac30d39fefd3cebf2fa9f9330202522da8241eb1338f5e2a159f5ba199312b41aba56baa6c8af443b49fce092cbda50dd055a1b09fe0a852fa0e7ee4d87aa8cd533d368cd1878f070c7c6c3a9c5a234b27d2a45309de60a959333cab89ad9af5223f41e3e891571349bc7a65dc53731aba9a00cccd45d34037d3b5cc9a2a079ddff55ebf003eac6d153f68f519c34b4b7d4e76107b9a17eb168abd4825c74e82d0d3040b8348453024835cf40601c71de87322863cc050c6269e7d63653b69334289b70f55db52adad1dafbb7ba77408f46cc48b5a6ba8089f96c0a5ac78ee5cf2aef0069d5fa57bf84fb24f9d6395e8765083d74cb422d40ca4c442bbbcc1396ed01f6e1bbd0acb45301b4709a72f58a5dfd177a86931e40615ccf27de341688c5536026ef6d4bae01311f7c9afa921fd29e8a4741d5adaac8e84a228c4fb642d4a16c27373e1177e25e4139e7fc43fe433eab02a96a1fed5494d4d27e2aa4dc7e22b3dfccb29c520f0afb9d57080528ff83837b70098c92ce5b7e74bd1326d45c6ce40a7efb0a4a4089f859e1cd2fcd0c5426fa5c7425917b21e3fe85e25954
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15888);
 script_version ("1.1");
 name["english"] = "Hydra: SSH2";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find SSH2 accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force SSH2 authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/ssh", 22);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#
thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/ssh");
if (! port) port = 22;
if (! get_port_state(port)) exit(0);

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
argv[i++] = "ssh2";

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
    set_kb_item(name: 'Hydra/ssh2/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following SSH accounts:\n' + report);
