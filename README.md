# go-cti

`go-cti` build a local copy of MITRE ATT&CK and CAPEC.

## Usage
```console
$ go-cti help
Go collect Cyber Threat Intelligence

Usage:
  go-cti [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  fetch       Fetch the data of mitre/cti
  help        Help about any command
  search      Search the data of mitre/cti form DB
  server      Start go-cti HTTP server
  version     Show version

Flags:
      --config string       config file (default is $HOME/.go-cti.yaml)
      --dbpath string       /path/to/sqlite3 or SQL connection string (default "$PWD/go-cti.sqlite3")
      --dbtype string       Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
      --debug               debug mode (default: false)
      --debug-sql           SQL debug mode
  -h, --help                help for go-cti
      --http-proxy string   http://proxy-url:port (default: empty)
      --log-dir string      /path/to/log (default "/var/log/go-cti")
      --log-json            output log as JSON
      --log-to-file         output log to file

Use "go-cti [command] --help" for more information about a command.
```

## Fetch MITRE ATT&CK and CAPEC
```console
$ go-cti fetch threat
INFO[04-15|00:19:57] Fetching Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings 
INFO[04-15|00:19:57] Fetching MITRE ATT&CK... 
INFO[04-15|00:19:59] Fetching CAPEC... 
INFO[04-15|00:20:00] Fetching CWE... 
INFO[04-15|00:20:04] Fetching NVD CVE...                      year=recent
INFO[04-15|00:20:05] Fetching NVD CVE...                      year=modified
INFO[04-15|00:20:06] Fetching NVD CVE...                      year=2002
INFO[04-15|00:20:09] Fetching NVD CVE...                      year=2003
INFO[04-15|00:20:10] Fetching NVD CVE...                      year=2004
INFO[04-15|00:20:12] Fetching NVD CVE...                      year=2005
INFO[04-15|00:20:15] Fetching NVD CVE...                      year=2006
INFO[04-15|00:20:18] Fetching NVD CVE...                      year=2007
INFO[04-15|00:20:21] Fetching NVD CVE...                      year=2008
INFO[04-15|00:20:25] Fetching NVD CVE...                      year=2009
INFO[04-15|00:20:28] Fetching NVD CVE...                      year=2010
INFO[04-15|00:20:30] Fetching NVD CVE...                      year=2011
INFO[04-15|00:20:34] Fetching NVD CVE...                      year=2012
INFO[04-15|00:20:37] Fetching NVD CVE...                      year=2013
INFO[04-15|00:20:41] Fetching NVD CVE...                      year=2014
INFO[04-15|00:20:44] Fetching NVD CVE...                      year=2015
INFO[04-15|00:20:47] Fetching NVD CVE...                      year=2016
INFO[04-15|00:20:51] Fetching NVD CVE...                      year=2017
INFO[04-15|00:20:56] Fetching NVD CVE...                      year=2018
INFO[04-15|00:21:01] Fetching NVD CVE...                      year=2019
INFO[04-15|00:21:08] Fetching NVD CVE...                      year=2020
INFO[04-15|00:21:13] Fetching NVD CVE...                      year=2021
INFO[04-15|00:21:18] Fetching NVD CVE...                      year=2022
INFO[04-15|00:21:21] Fetched Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings ctis=1112 mappings=97710
INFO[04-15|00:21:21] Insert Cyber Threat Intelligences and CVE-ID to CTI-ID Mappings into go-cti. db=sqlite3
INFO[04-15|00:21:21] Inserting Cyber Threat Intelligences... 
1112 / 1112 [--------------------------------------------------------------------------] 100.00% 2067 p/s
INFO[04-15|00:21:22] Inserting CVE-ID to CTI-ID Mappings... 
97710 / 97710 [-----------------------------------------------------------------------] 100.00% 10084 p/s
```

## Search by CVE-ID
```
$ go-cti search CVE-2017-15131
[
  {
    "cti_id": "T1546.001",
    "type": "MITRE-ATTACK",
    "name": "T1546.001: Change Default File Association",
    // ...
  },
  // ...
]
```

## Sever mode
```console
$ go-cti server
INFO[04-15|00:23:43] Starting HTTP Server... 
INFO[04-15|00:23:43] Listening...                             URL=127.0.0.1:1329

   ____    __
  / __/___/ /  ___
 / _// __/ _ \/ _ \
/___/\__/_//_/\___/ v3.3.10-dev
High performance, minimalist Go web framework
https://echo.labstack.com
____________________________________O/_______
                                    O\
⇨ http server started on 127.0.0.1:1329
{"time":"2022-04-15T00:24:23.773648507+09:00","id":"","remote_ip":"127.0.0.1","host":"127.0.0.1:1329","method":"GET","uri":"/cves/CVE-2017-15131","user_agent":"curl/7.68.0","status":200,"error":"","latency":143229557,"latency_human":"143.229557ms","bytes_in":0,"bytes_out":358064}
{"time":"2022-04-15T00:26:34.068344126+09:00","id":"","remote_ip":"127.0.0.1","host":"127.0.0.1:1329","method":"POST","uri":"/multi-cves","user_agent":"curl/7.68.0","status":200,"error":"","latency":137130582,"latency_human":"137.130582ms","bytes_in":28,"bytes_out":358083}

$ curl http://127.0.0.1:1329/cves/CVE-2017-15131 | jq
[
  {
    "cti_id": "T1546.001",
    "type": "MITRE-ATTACK",
    "name": "T1546.001: Change Default File Association",
    // ...
  },
  // ...
]

$ curl -d "{\"args\": [\"CVE-2017-15131\"]}" -H "Content-Type: application/json" 127.0.0.1:1329/multi-cves| jq .
{
  "CVE-2017-15131": [
    {
      "cti_id": "T1546.001",
      "type": "MITRE-ATTACK",
      "name": "T1546.001: Change Default File Association"
      // ...
    },
    // ...
  ]
}
```

## License
MIT

## Author
[MaineK00n](https://twitter.com/MaineK00n)