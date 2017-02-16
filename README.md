# Shodan_cmd
Search host, range of hosts or exploits in Shodan and save results in a file.

# How it work
Cloning this repo to your computer typing on your terminal:<br/>
<code>git clone https://github.com/Va5c0/Shodan_cmd.git</code>

Type <code>./shodan_cmd.py -h</code> to see help.<br/>
Type <code>./shodan_cmd.py</code> to see examples.<br/>

Use examples:

1. Get information about:<br/>
  - API: <code>./shodan_cmd.py -I api</code>
  - Protocols: <code>./shodan_cmd.py -I protocols</code>
  - Services: <code>./shodan_cmd.py -I services</code>
  - Queries: <code>./shodan_cmd.py -I queries -p [pag num] --sort [votes/timestamp] --order [desc/asc]</code>
  
2. Search in queries posted by users.<br/>
<code>./shodan_cmd.py -Q [query] -p [pag num]</code>

3. Search in Shodan.<br/>
<code>./shodan_cmd.py -S [query] -p [pag num]</code>

4. Get info about host.<br/>
<code>./shodan_cmd.py -H [host]</code>

5. Search a range of hosts.<br/>
<code>./shodan_cmd.py  -R [ip/range]</code>

6. Search exploits.<br/>
<code>./shodan_cmd.py -E [query]
  - Possible search filters:<br/>
    author  bid   code    cve   date    platform<br/>
    type  osvdb   msb     port  title   description<br/>
  - Example:<code>./shodan_cmd.py -E 'ftp type:remote platform:linux'</code>
  
7. Show a report with selected field/s.<br/>
<code>./shodan_cmd.py -S [query] -r [field/s]</code>
  - Possible fields.<br/>
    product   ip_str    port    hostnames   city<br/>
    longitude   latitude    country_name    os<br/>
    timestamp   transport   data    isp     asn<br/>
  - Example:<code>./shodan_cmd.py -S 'ftp anonymous user logged in' -r ip_str,city</code>
  
### All options support the argument [-o] to save result in a file. ###<br/>

# Version
Shodan_cmd V1.0
