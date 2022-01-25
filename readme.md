### clean
```ruby
ruby rakefile.rb --clean
```
This command will remove any text files that are in the current directory. 

```ruby
rake clean
```


### Reverse Shell
```ruby
ruby rakefile.rb --rs 127.0.0.1 2222
```
This command needs an IP and a port. This command will output a string that when ran will create a cronjob on the system that will 
use netcat to connect to the command server. 

```ruby
rake rs["127.0.0.1","2222"]
```
`127.0.0.1` is the IP and `2222` is the port. 


### Crawl
```ruby
ruby rakefile.rb --crawl https://google.com/
```

The crawl command will crawl every URL on the site & create a txt file that contains all the links.

```ruby
rake crawl["https://google.com"]
```


### Nmap service scan

```ruby
ruby rakefile.rb --sv 192.168.1.110
```
It will use Nmap to perform a service scan (-sV) on the given IP. Nmap must be installed on the system.
```ruby
rake sv["192.168.1.110"]
```

### Nmap UDP scan
```ruby
sudo rake udp["192.168.2.220"]
```
This will perform a UDP scan on the target and create a text file with the details. This command must be ran with sudo. Again, nmap has to be installed on the computer.

```ruby
sudo ruby rakefile.rb --sv 192.168.1.220
```