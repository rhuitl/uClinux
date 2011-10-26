#TRUSTED 43db7592f7d8c3d8c615614927d559cb21bc4363eafe202196d15bd68ffda6b0ca57e0cb6a26f30aa90334b8663417f69bd4becb1330271d220bd68837d09a737ebb2e85091396682f677302a89aff5e39945d5b909bc3cdaa753d118b2dd4d2eb5ae1c4018c10091371864649eeb7e303ff23d74bcd8a4bc423dd9d451b74b8657206b715fc51f09da20b9ff3ac961b860f3f5ffc7adf25d6acd4c6d5843b8eb73d1929e06a50bca01d802d248c44bd15d40d2505ba80368a0aec385e05998cd01c770b5ef0d0352db4bcd53377c7ecedabe6df21ab23d641aeb42acf31806be8a77cf57796611b19767d57d504b681d43b6b47eff518fe24808f42cbaf054a27ecc6cb666c9321466cb9f3a227128f030f7339a086116087333503a97ce19d2828b94bbb8534817929c5a825f2d099dc6ccb71702927b6f1e1f532530739cf599590126067432f91c976468ce818b940234f0745e2a24f4e53b6ef0ff30d0dc2a6d51981ce79b5bfd690a555c5c336baa8019cdc80bb0bd2a11f6f43df771fff5d66b5630fff6a3fbe207e6468c3f021e4dc440f9554156413e51ec52481e124636735d68d1d2bbac9a90b861d8ee585082477f42bb816a4b016a31314a19d9fab414f99f0891abe5a61ae89b605b2e0218acc6bd965c74f79b468f47977375ea2dc6a2e439334f5b13d68884fa177ee8bbcc83e19c75247cdcdbfd76d6094
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15872);
 script_version ("1.2");
 name["english"] = "Hydra: FTP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find FTP accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force FTP authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/ftp", 21);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "find_service_3digits.nasl");
 exit(0);
}

#
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/ftp");
if (! port) port = 21;
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
argv[i++] = "ftp";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword:', p, '\n');
    set_kb_item(name: 'Hydra/ftp/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following FTP accounts:\n' + report);
