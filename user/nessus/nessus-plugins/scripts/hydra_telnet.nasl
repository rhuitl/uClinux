#TRUSTED 4275669cded24a30ea56f0508cd772b4fd1d966b109bf37c77e03c0a8d2943b9bc77a00f243072f0f97997b1402162a7dcb0d0b54782787de1d3c0b47ba949c4422e3a24de4ac2dc7b639a4030f2351d353fc11dc9fa7281abd004ccf8154ad10503ec662e85f4b51a0cd6712cdc14d92ce4e6a79716115e5925c9613ebf979c2c78378c718c0633f88632a29c48b2554e7da5f8086e560759710d2a4661bb8e78528ece7808e22861777533fcf97a6f178002ff20122d7163447a8b45559be695cd53cbb43c1aa2c500e3dd46556acb0f48d7b0be4385e48a06e70a2e2d7151fc4397681b9bfd40f8239d8e14857c43928f92770e4244e3f03df5ed6c8d5350b939a708aef13d73ea421489105aefd449e5f0fb953155f1322f1d4fe2a9b5cc00fb0ce47e88b57122316ac7f2fffeb6218282582ff0cd98375db63925bbefd870ebd1b695884d6d6a61fce9465cedb4d134652f5416f896ad267191678fdaf2c9b648e11e8ab0811b5e5dcf64f46f431e23af4701beb4443ee1d742741c7c88720b8ebcd19597c456e1d8bb2ff5d34045c434494fea98cfadfdf85c7209cb3718abb6569782be44c158f3efa513acde6eb533897a147e1aa58b2842a39b57af41cb67452bf9253bdca87d0eb2879d3370fec113e09713644271cfc6b37bd02f9e0c818d7d11f470c83b23942ec519b1c2df2547dd871c07c346eb81ad08b6b4
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15889);
 script_version ("1.1");
 name["english"] = "Hydra: telnet";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find telnet passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force telnet authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#
thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/telnet");
if (! port) port = 23;
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
argv[i++] = "telnet";

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
    set_kb_item(name: 'Hydra/telnet/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following Telnet accounts:\n' + report);
