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
INFO[04-20|11:39:27] Fetching Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings 
INFO[04-20|11:39:27] Fetching MITRE ATT&CK... 
INFO[04-20|11:39:30] Fetching CAPEC... 
INFO[04-20|11:39:31] Fetching CWE... 
INFO[04-20|11:39:34] Fetching NVD CVE...                      year=recent
INFO[04-20|11:39:35] Fetching NVD CVE...                      year=modified
INFO[04-20|11:39:37] Fetching NVD CVE...                      year=2002
INFO[04-20|11:39:39] Fetching NVD CVE...                      year=2003
INFO[04-20|11:39:40] Fetching NVD CVE...                      year=2004
INFO[04-20|11:39:42] Fetching NVD CVE...                      year=2005
INFO[04-20|11:39:43] Fetching NVD CVE...                      year=2006
INFO[04-20|11:39:46] Fetching NVD CVE...                      year=2007
INFO[04-20|11:39:48] Fetching NVD CVE...                      year=2008
INFO[04-20|11:39:51] Fetching NVD CVE...                      year=2009
INFO[04-20|11:39:53] Fetching NVD CVE...                      year=2010
INFO[04-20|11:39:55] Fetching NVD CVE...                      year=2011
INFO[04-20|11:39:58] Fetching NVD CVE...                      year=2012
INFO[04-20|11:40:00] Fetching NVD CVE...                      year=2013
INFO[04-20|11:40:03] Fetching NVD CVE...                      year=2014
INFO[04-20|11:40:05] Fetching NVD CVE...                      year=2015
INFO[04-20|11:40:08] Fetching NVD CVE...                      year=2016
INFO[04-20|11:40:11] Fetching NVD CVE...                      year=2017
INFO[04-20|11:40:15] Fetching NVD CVE...                      year=2018
INFO[04-20|11:40:19] Fetching NVD CVE...                      year=2019
INFO[04-20|11:40:23] Fetching NVD CVE...                      year=2020
INFO[04-20|11:40:28] Fetching NVD CVE...                      year=2021
INFO[04-20|11:40:33] Fetching NVD CVE...                      year=2022
INFO[04-20|11:40:35] Fetched Cyber Threat Intelligence and CVE-ID to CTI-ID Mappings techniques=1112 mappings=98011 attackers=672
INFO[04-20|11:40:35] Insert Cyber Threat Intelligences and CVE-ID to CTI-ID Mappings into go-cti. db=redis
INFO[04-20|11:40:35] Inserting Cyber Threat Intelligences... 
INFO[04-20|11:43:29] Inserting Techniques... 
1112 / 1112 [------------------------------------------------] 100.00% 3530 p/s
INFO[04-20|11:43:30] Inserting CVE-ID to CTI-ID CveToTechniques... 
98011 / 98011 [----------------------------------------------] 100.00% 9900 p/s
INFO[04-20|11:43:40] Inserting Attackers... 
672 / 672 [-----------------------------------------------------] 100.00% ? p/s
```

## Search by CVE-ID
```
$ go-cti search cti T1037
{
  "type": "Technique",
  "technique": {
    "technique_id": "T1037",
    "type": "MITRE-ATTACK",
    "name": "T1037: Boot or Logon Initialization Scripts",
	...
  }
}

$ go-cti search cve CVE-2017-15131
[
  "T1037",
  "CAPEC-578",
  "T1562.001",
  "T1014",
  "CAPEC-502",
  "CAPEC-551",
  "T1547.006",
  "T1080",
  "CAPEC-563",
  "T1546.004",
  "T1574.011",
  "CAPEC-536",
  "CAPEC-550",
  "T1542.003",
  "CAPEC-19",
  "T1543.002",
  "CAPEC-503",
  "T1553.004",
  "T1546.001",
  "CAPEC-564",
  "T1547",
  "CAPEC-478",
  "CAPEC-558",
  "CAPEC-562",
  "CAPEC-546",
  "T1543.004",
  "CAPEC-552",
  "CAPEC-556",
  "CAPEC-479",
  "T1543.003",
  "T1546.008",
  "T1543.001",
  "CAPEC-441"
]

$ search attacker T1078 T1550.002 T1588.002
[
  "S0122", // T1550.002
  "G0011"  // T1078, T1588.002
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
{"time":"2022-04-15T00:24:23.773648507+09:00","id":"","remote_ip":"127.0.0.1","host":"127.0.0.1:1329","method":"GET","uri":"/cves/CVE-2021-46628","user_agent":"curl/7.68.0","status":200,"error":"","latency":143229557,"latency_human":"143.229557ms","bytes_in":0,"bytes_out":358064}
{"time":"2022-04-15T00:26:34.068344126+09:00","id":"","remote_ip":"127.0.0.1","host":"127.0.0.1:1329","method":"POST","uri":"/multi-cves","user_agent":"curl/7.68.0","status":200,"error":"","latency":137130582,"latency_human":"137.130582ms","bytes_in":28,"bytes_out":358083}

$ curl http://127.0.0.1:1329/ctis/CAPEC-540 | jq .
{
  "type": "Technique",
  "technique": {
    "technique_id": "CAPEC-540",
    "type": "CAPEC",
    "name": "CAPEC-540: Overread Buffers",
	// ...
  }
}

$ curl http://127.0.0.1:1329/cves/CVE-2021-46628 | jq .
[
  "CAPEC-540"
]


$ curl -d "{\"args\": [\"CVE-2021-46628\"]}" -H "Content-Type: application/json" 127.0.0.1:1329/multi-cves | jq .
{
  "CVE-2021-46628": [
    "CAPEC-540"
  ]
}
```

## How to generate the Technique Dictionary for Vuls
- main.go
```go
package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/exp/slices"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	ctiDB "github.com/vulsio/go-cti/db"
	"github.com/vulsio/go-cti/models"
)

func main() {
	db, err := gorm.Open(sqlite.Open("go-cti.sqlite3"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open DB. err: %s\n", err)
		os.Exit(1)
	}
	techniqueIDs := []string{}
	if err := db.Model(&models.Technique{}).Select("technique_id").Find(&techniqueIDs).Error; err != nil {
		fmt.Fprintf(os.Stderr, "failed to get techniqueIDs. err: %s\n", err)
		os.Exit(1)
	}
	sqlDB, err := db.DB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get sqlDB. err: %s\n", err)
		os.Exit(1)
	}
	if err := sqlDB.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close sqlDB. err: %s\n", err)
		os.Exit(1)
	}

	driver, locked, err := ctiDB.NewDB("sqlite3", "go-cti.sqlite3", false, ctiDB.Option{})
	if locked || err != nil {
		fmt.Fprintf(os.Stderr, "failed to new DB. locked: %t, err: %s\n", locked, err)
		os.Exit(1)
	}

	fmt.Println("// Technique has MITER ATT&CK Technique or CAPEC information")
	fmt.Printf("type Technique struct {\n  Name string `json:\"name\"`\n  Platforms []string `json:\"platforms\"`\n}\n\n")
	fmt.Println("// TechniqueDict is the MITRE ATT&CK Technique and CAPEC dictionary")
	fmt.Printf("var TechniqueDict = map[string]Technique{\n")
	slices.Sort(techniqueIDs)
	for _, techniqueID := range techniqueIDs {
		cti, err := driver.GetCtiByCtiID(techniqueID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get CTI. err: %s\n", err)
			os.Exit(1)
		}

		if cti.Technique.Type == models.MitreAttackType {
			tactics := []string{}
			for _, phase := range cti.Technique.MitreAttack.KillChainPhases {
				tactics = append(tactics, phase.Tactic)
			}
			slices.Sort(tactics)

			platforms := []string{}
			for _, platform := range cti.Technique.MitreAttack.Platforms {
				platforms = append(platforms, fmt.Sprintf("\"%s\"", platform.Platform))
			}
			slices.Sort(platforms)

			fmt.Printf("\"%s\": {\n  Name:      %q,\n  Platforms: []string{%s},\n},\n",
				cti.Technique.TechniqueID,
				fmt.Sprintf("%s => %s", strings.Join(tactics, ", "), cti.Technique.Name),
				strings.Join(platforms, ", "),
			)
		} else {
			fmt.Printf("\"%s\": {\n  Name: %q,\n},\n",
				cti.Technique.TechniqueID,
				cti.Technique.Name,
			)
		}
	}
	fmt.Println("}")

	if err := driver.CloseDB(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close DB. err: %s", err)
		os.Exit(1)
	}
}
```

```console
$ ls
go-cti.sqlite3  go.mod  go.sum  main.go

$ go run main.go
```

## License
MIT

## Author
[MaineK00n](https://twitter.com/MaineK00n)