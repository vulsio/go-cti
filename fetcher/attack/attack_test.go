package attack

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vulsio/go-cti/models"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		expected []models.Cti
		wantErr  bool
	}{
		{
			in: "testdata/enterprise-attack.json",
			expected: []models.Cti{
				{
					CtiID:       "T1003",
					Type:        models.MitreAttackType,
					Name:        "T1003: OS Credential Dumping",
					Description: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.\n\nSeveral of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.\n",
					References: []models.Reference{
						{
							SourceName:  "Medium Detecting Attempts to Steal Passwords from Memory",
							Description: "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
							URL:         "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
						},
						{
							SourceName:  "Powersploit",
							Description: "PowerSploit. (n.d.). Retrieved December 4, 2014.",
							URL:         "https://github.com/mattifestation/PowerSploit",
						},
						{
							SourceName:  "Microsoft DRSR Dec 2017",
							Description: "Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.",
							URL:         "https://msdn.microsoft.com/library/cc228086.aspx",
						},
						{
							SourceName:  "Microsoft GetNCCChanges",
							Description: "Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.",
							URL:         "https://msdn.microsoft.com/library/dd207691.aspx",
						},
						{
							SourceName:  "Samba DRSUAPI",
							Description: "SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.",
							URL:         "https://wiki.samba.org/index.php/DRSUAPI",
						},
						{
							SourceName:  "Harmj0y DCSync Sept 2015",
							Description: "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.",
							URL:         "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
						},
						{
							SourceName:  "Microsoft NRPC Dec 2017",
							Description: "Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.",
							URL:         "https://msdn.microsoft.com/library/cc237008.aspx",
						},
						{
							SourceName:  "Microsoft SAMR",
							Description: "Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.",
							URL:         "https://msdn.microsoft.com/library/cc245496.aspx",
						},
						{
							SourceName:  "AdSecurity DCSync Sept 2015",
							Description: "Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.",
							URL:         "https://adsecurity.org/?p=1729",
						},
						{
							SourceName:  "Microsoft LSA",
							Description: "Microsoft. (2013, July 31). Configuring Additional LSA Protection. Retrieved February 13, 2015.",
							URL:         "https://technet.microsoft.com/en-us/library/dn408187.aspx",
						},
						{
							SourceName:  "Symantec Sowbug Nov 2017",
							Description: "Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.",
							URL:         "https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments",
						},
						{
							SourceName:  "FireEye Periscope March 2018",
							Description: "FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.",
							URL:         "https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html",
						},
						{
							SourceName:  "GitHub Pupy",
							Description: "Nicolas Verdier. (n.d.). Retrieved January 29, 2018.",
							URL:         "https://github.com/n1nj4sec/pupy",
						},
					},
					Mitigations: []models.Mitigation{
						{
							Name:        "M1025: Privileged Process Integrity",
							Description: "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures.",
						},
					},
					MitreAttack: &models.MitreAttack{
						CapecIDs: []models.CapecID{
							{CapecID: "CAPEC-test"},
						},
						Detection:       "### Windows\nMonitor for unexpected processes interacting with lsass.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as [Mimikatz](https://attack.mitre.org/software/S0002) access the LSA Subsystem Service (LSASS) process by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective [Process Injection](https://attack.mitre.org/techniques/T1055) to reduce potential indicators of malicious activity.\n\nHash dumpers open the Security Accounts Manager (SAM) on the local file system (%SystemRoot%/system32/config/SAM) or create a dump of the Registry SAM key to access stored account password hashes. Some hash dumpers will open the local file system as a device and parse to the SAM table to avoid file access defenses. Others will make an in-memory copy of the SAM table before reading hashes. Detection of compromised [Valid Accounts](https://attack.mitre.org/techniques/T1078) in-use by adversaries may help as well. \n\nOn Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.\n\nMonitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like [Mimikatz](https://attack.mitre.org/software/S0002). [PowerShell](https://attack.mitre.org/techniques/T1059/001) scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module, (Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.\n\nMonitor domain controller logs for replication requests and other unscheduled activity possibly associated with DCSync. (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) Note: Domain controllers may not log replication requests originating from the default domain controller account. (Citation: Harmj0y DCSync Sept 2015). Also monitor for network protocols  (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft NRPC Dec 2017) and other replication requests (Citation: Microsoft SAMR) from IPs not associated with known domain controllers. (Citation: AdSecurity DCSync Sept 2015)\n\n### Linux\nTo obtain the passwords and hashes stored in memory, processes must open a maps file in the /proc filesystem for the process being analyzed. This file is stored under the path <code>/proc/<pid>/maps</code>, where the <code><pid></code> directory is the unique pid of the program being interrogated for such authentication data. The AuditD monitoring tool, which ships stock in many Linux distributions, can be used to watch for hostile processes opening this file in the proc file system, alerting on the pid, process name, and arguments of such programs.",
						KillChainPhases: "TA0006: Credential Access",
						DataSources: []models.DataSource{
							{
								Name:        "DS0009: Process: Process Creation",
								Description: "Birth of a new running process (ex: Sysmon EID 1 or Windows EID 4688)",
							},
						},
						Procedures: []models.Procedure{
							{
								Name:        "G0054: Sowbug",
								Description: "[Sowbug](https://attack.mitre.org/groups/G0054) is a threat group that has conducted targeted attacks against organizations in South America and Southeast Asia, particularly government entities, since at least 2015. (Citation: Symantec Sowbug Nov 2017)",
							},
							{
								Name:        "S0232: HOMEFRY",
								Description: "[HOMEFRY](https://attack.mitre.org/software/S0232) is a 64-bit Windows password dumper/cracker that has previously been used in conjunction with other [Leviathan](https://attack.mitre.org/groups/G0065) backdoors. (Citation: FireEye Periscope March 2018)",
							},
							{
								Name:        "S0192: Pupy",
								Description: "[Pupy](https://attack.mitre.org/software/S0192) is an open source, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool. (Citation: GitHub Pupy) It is written in Python and can be generated as a payload in several different ways (Windows exe, Python file, PowerShell oneliner/file, Linux elf, APK, Rubber Ducky, etc.). (Citation: GitHub Pupy) [Pupy](https://attack.mitre.org/software/S0192) is publicly available on GitHub. (Citation: GitHub Pupy)",
							},
						},
						Platforms:            "Linux, Windows, macOS",
						PermissionsRequired:  "Administrator, SYSTEM, root",
						EffectivePermissions: "SYSTEM",
						DefenseBypassed:      "System Access Controls",
						ImpactType:           "test",
						NetworkRequirements:  true,
						RemoteSupport:        true,
						SubTechniques: []models.SubTechnique{
							{
								Name: "T1003.008: /etc/passwd and /etc/shadow",
							},
						},
					},
					Capec:    nil,
					Created:  time.Date(2017, time.May, 31, 21, 30, 19, 735*int(time.Millisecond), time.UTC),
					Modified: time.Date(2021, time.October, 15, 19, 55, 01, 922*int(time.Millisecond), time.UTC),
				},
				{
					CtiID:       "T1003.008",
					Type:        models.MitreAttackType,
					Name:        "T1003.008: /etc/passwd and /etc/shadow",
					Description: "Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user.(Citation: Linux Password and Shadow File Formats)\n\nThe Linux utility, unshadow, can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper:(Citation: nixCraft - John the Ripper) <code># /usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db</code>\n",
					References: []models.Reference{
						{
							SourceName:  "Linux Password and Shadow File Formats",
							Description: "The Linux Documentation Project. (n.d.). Linux Password and Shadow File Formats. Retrieved February 19, 2020.",
							URL:         "https://www.tldp.org/LDP/lame/LAME/linux-admin-made-easy/shadow-file-formats.html",
						},
						{
							SourceName:  "nixCraft - John the Ripper",
							Description: "Vivek Gite. (2014, September 17). Linux Password Cracking: Explain unshadow and john Commands (John the Ripper Tool). Retrieved February 19, 2020.",
							URL:         "https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/",
						},
					},
					Mitigations: []models.Mitigation{},
					MitreAttack: &models.MitreAttack{
						CapecIDs:            []models.CapecID{},
						Detection:           "The AuditD monitoring tool, which ships stock in many Linux distributions, can be used to watch for hostile processes attempting to access <code>/etc/passwd</code> and <code>/etc/shadow</code>, alerting on the pid, process name, and arguments of such programs.",
						KillChainPhases:     "TA0006: Credential Access",
						DataSources:         []models.DataSource{},
						Procedures:          []models.Procedure{},
						Platforms:           "Linux",
						PermissionsRequired: "root",
						SubTechniques:       []models.SubTechnique{},
					},
					Capec:    nil,
					Created:  time.Date(2020, time.February, 11, 18, 46, 56, 263*int(time.Millisecond), time.UTC),
					Modified: time.Date(2020, time.March, 20, 15, 56, 55, 22*int(time.Millisecond), time.UTC),
				},
			},
		},
		{
			in:       "testdata/deprecated.json",
			expected: []models.Cti{},
		},
		{
			in:      "testdata/fail_get_addinfo.json",
			wantErr: true,
		},
		{
			in:      "testdata/fail_get_deta_source.json",
			wantErr: true,
		},
		{
			in:      "testdata/fail_get_kill_chain_phase.json",
			wantErr: true,
		},
	}

	for i, tt := range tests {
		res, err := os.ReadFile(tt.in)
		if err != nil {
			t.Fatalf("[%d] Failed to read file. err: %s", i, err)
		}
		actual, err := parse(res)
		if err != nil {
			if tt.wantErr {
				continue
			}
			t.Fatalf("[%d] Failed to parse. err: %s", i, err)
		}

		opts := []cmp.Option{
			cmpopts.SortSlices(func(i, j models.Cti) bool {
				return i.CtiID < j.CtiID
			}),
		}
		if diff := cmp.Diff(actual, tt.expected, opts...); diff != "" {
			t.Errorf("[%d] parse diff: (-got +want)\n%s", i, diff)
		}
	}
}
