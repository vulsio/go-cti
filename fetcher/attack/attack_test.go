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
		in                 string
		expectedTechniques []models.Technique
		expectedAttackers  []models.Attacker
		wantErr            bool
	}{
		{
			in: "testdata/enterprise-attack.json",
			expectedTechniques: []models.Technique{
				{
					TechniqueID: "T1003",
					Type:        models.MitreAttackType,
					Name:        "T1003: OS Credential Dumping",
					Description: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.\n\nSeveral of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.\n",
					References: []models.TechniqueReference{
						{
							Reference: models.Reference{
								SourceName:  "AdSecurity DCSync Sept 2015",
								Description: "Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.",
								URL:         "https://adsecurity.org/?p=1729",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "FireEye Periscope March 2018",
								Description: "FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.",
								URL:         "https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "GitHub Pupy",
								Description: "Nicolas Verdier. (n.d.). Retrieved January 29, 2018.",
								URL:         "https://github.com/n1nj4sec/pupy",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Harmj0y DCSync Sept 2015",
								Description: "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.",
								URL:         "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Mandiant UNC3890 Aug 2022",
								Description: "Mandiant Israel Research Team. (2022, August 17). Suspected Iranian Actor Targeting Israeli Shipping, Healthcare, Government and Energy Sectors. Retrieved September 21, 2022.",
								URL:         "https://www.mandiant.com/resources/blog/suspected-iranian-actor-targeting-israeli-shipping",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Medium Detecting Attempts to Steal Passwords from Memory",
								Description: "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
								URL:         "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Microsoft DRSR Dec 2017",
								Description: "Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.",
								URL:         "https://msdn.microsoft.com/library/cc228086.aspx",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Microsoft GetNCCChanges",
								Description: "Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.",
								URL:         "https://msdn.microsoft.com/library/dd207691.aspx",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Microsoft NRPC Dec 2017",
								Description: "Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.",
								URL:         "https://msdn.microsoft.com/library/cc237008.aspx",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Microsoft SAMR",
								Description: "Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.",
								URL:         "https://msdn.microsoft.com/library/cc245496.aspx"},
						},
						{
							Reference: models.Reference{
								SourceName:  "Microsoft LSA",
								Description: "Microsoft. (2013, July 31). Configuring Additional LSA Protection. Retrieved February 13, 2015.",
								URL:         "https://technet.microsoft.com/en-us/library/dn408187.aspx"},
						},
						{
							Reference: models.Reference{
								SourceName:  "Powersploit",
								Description: "PowerSploit. (n.d.). Retrieved December 4, 2014.",
								URL:         "https://github.com/mattifestation/PowerSploit",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Samba DRSUAPI",
								Description: "SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.",
								URL:         "https://wiki.samba.org/index.php/DRSUAPI",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Symantec Sowbug Nov 2017",
								Description: "Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.",
								URL:         "https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments",
							},
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
						Detection: "### Windows\nMonitor for unexpected processes interacting with lsass.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as [Mimikatz](https://attack.mitre.org/software/S0002) access the LSA Subsystem Service (LSASS) process by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective [Process Injection](https://attack.mitre.org/techniques/T1055) to reduce potential indicators of malicious activity.\n\nHash dumpers open the Security Accounts Manager (SAM) on the local file system (%SystemRoot%/system32/config/SAM) or create a dump of the Registry SAM key to access stored account password hashes. Some hash dumpers will open the local file system as a device and parse to the SAM table to avoid file access defenses. Others will make an in-memory copy of the SAM table before reading hashes. Detection of compromised [Valid Accounts](https://attack.mitre.org/techniques/T1078) in-use by adversaries may help as well. \n\nOn Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.\n\nMonitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like [Mimikatz](https://attack.mitre.org/software/S0002). [PowerShell](https://attack.mitre.org/techniques/T1059/001) scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module, (Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.\n\nMonitor domain controller logs for replication requests and other unscheduled activity possibly associated with DCSync. (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) Note: Domain controllers may not log replication requests originating from the default domain controller account. (Citation: Harmj0y DCSync Sept 2015). Also monitor for network protocols  (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft NRPC Dec 2017) and other replication requests (Citation: Microsoft SAMR) from IPs not associated with known domain controllers. (Citation: AdSecurity DCSync Sept 2015)\n\n### Linux\nTo obtain the passwords and hashes stored in memory, processes must open a maps file in the /proc filesystem for the process being analyzed. This file is stored under the path <code>/proc/<pid>/maps</code>, where the <code><pid></code> directory is the unique pid of the program being interrogated for such authentication data. The AuditD monitoring tool, which ships stock in many Linux distributions, can be used to watch for hostile processes opening this file in the proc file system, alerting on the pid, process name, and arguments of such programs.",
						KillChainPhases: []models.KillChainPhase{
							{Tactic: "TA0006: Credential Access"},
						},
						DataSources: []models.DataSource{},
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
							{
								Name:        "C0010: C0010",
								Description: "[C0010](https://attack.mitre.org/campaigns/C0010) was a cyber espionage campaign conducted by UNC3890 that targeted Israeli shipping, government, aviation, energy, and healthcare organizations. Security researcher assess UNC3890 conducts operations in support of Iranian interests, and noted several limited technical connections to Iran, including PDB strings and Farsi language artifacts. [C0010](https://attack.mitre.org/campaigns/C0010) began by at least late 2020, and was still ongoing as of mid-2022.(Citation: Mandiant UNC3890 Aug 2022)",
							},
						},
						Platforms: []models.TechniquePlatform{
							{Platform: "Linux"},
							{Platform: "Windows"},
							{Platform: "macOS"},
						},
						PermissionsRequired: []models.PermissionRequired{
							{Permission: "Administrator"},
							{Permission: "SYSTEM"},
							{Permission: "root"},
						},
						EffectivePermissions: []models.EffectivePermission{
							{Permission: "SYSTEM"},
						},
						DefenseBypassed: []models.DefenseBypassed{
							{Defense: "System Access Controls"},
						},
						ImpactType: []models.ImpactType{
							{Type: "test"},
						},
						NetworkRequirements: true,
						RemoteSupport:       true,
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
					TechniqueID: "T1003.008",
					Type:        models.MitreAttackType,
					Name:        "T1003.008: /etc/passwd and /etc/shadow",
					Description: "Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user.(Citation: Linux Password and Shadow File Formats)\n\nThe Linux utility, unshadow, can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper:(Citation: nixCraft - John the Ripper) <code># /usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db</code>\n",
					References: []models.TechniqueReference{
						{
							Reference: models.Reference{
								SourceName:  "Linux Password and Shadow File Formats",
								Description: "The Linux Documentation Project. (n.d.). Linux Password and Shadow File Formats. Retrieved February 19, 2020.",
								URL:         "https://www.tldp.org/LDP/lame/LAME/linux-admin-made-easy/shadow-file-formats.html",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "nixCraft - John the Ripper",
								Description: "Vivek Gite. (2014, September 17). Linux Password Cracking: Explain unshadow and john Commands (John the Ripper Tool). Retrieved February 19, 2020.",
								URL:         "https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/",
							},
						},
					},
					Mitigations: []models.Mitigation{},
					MitreAttack: &models.MitreAttack{
						CapecIDs:  []models.CapecID{},
						Detection: "The AuditD monitoring tool, which ships stock in many Linux distributions, can be used to watch for hostile processes attempting to access <code>/etc/passwd</code> and <code>/etc/shadow</code>, alerting on the pid, process name, and arguments of such programs.",
						KillChainPhases: []models.KillChainPhase{
							{Tactic: "TA0006: Credential Access"},
						},
						DataSources: []models.DataSource{},
						Procedures:  []models.Procedure{},
						Platforms: []models.TechniquePlatform{
							{Platform: "Linux"},
						},
						PermissionsRequired: []models.PermissionRequired{
							{Permission: "root"},
						},
						EffectivePermissions: []models.EffectivePermission{},
						DefenseBypassed:      []models.DefenseBypassed{},
						ImpactType:           []models.ImpactType{},
						SubTechniques:        []models.SubTechnique{},
					},
					Capec:    nil,
					Created:  time.Date(2020, time.February, 11, 18, 46, 56, 263*int(time.Millisecond), time.UTC),
					Modified: time.Date(2020, time.March, 20, 15, 56, 55, 22*int(time.Millisecond), time.UTC),
				},
			},
			expectedAttackers: []models.Attacker{
				{
					AttackerID:  "G0054",
					Type:        models.GroupType,
					Name:        "G0054: Sowbug",
					Description: "[Sowbug](https://attack.mitre.org/groups/G0054) is a threat group that has conducted targeted attacks against organizations in South America and Southeast Asia, particularly government entities, since at least 2015. (Citation: Symantec Sowbug Nov 2017)",
					TechniquesUsed: []models.TechniqueUsed{
						{
							TechniqueID: "T1003",
							Name:        "T1003: OS Credential Dumping",
							Use:         "[Sowbug](https://attack.mitre.org/groups/G0054) has used credential dumping tools.(Citation: Symantec Sowbug Nov 2017)",
						},
					},
					References: []models.AttackerReference{
						{
							Reference: models.Reference{
								SourceName:  "Symantec Sowbug Nov 2017",
								Description: "Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.",
								URL:         "https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Symantec Buckeye",
								Description: "Symantec Security Response. (2016, September 6). Buckeye cyberespionage group shifts gaze from US to Hong Kong. Retrieved September 26, 2016.",
								URL:         "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong",
							},
						},
					},
					Group: &models.AttackerGroup{
						AssociatedGroups: []models.AssociatedGroup{
							{
								Name:        "test",
								Description: "test",
							},
						},
						SoftwaresUsed: []models.SoftwareUsed{
							{
								Name:        "S0232: HOMEFRY",
								Description: "(Citation: Symantec Buckeye)",
							},
						},
					},
					Created:  time.Date(2018, time.January, 16, 16, 13, 52, 465*int(time.Millisecond), time.UTC),
					Modified: time.Date(2020, time.March, 30, 2, 46, 16, 483*int(time.Millisecond), time.UTC),
				},
				{
					AttackerID:  "S0192",
					Type:        models.SoftwareType,
					Name:        "S0192: Pupy",
					Description: "[Pupy](https://attack.mitre.org/software/S0192) is an open source, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool. (Citation: GitHub Pupy) It is written in Python and can be generated as a payload in several different ways (Windows exe, Python file, PowerShell oneliner/file, Linux elf, APK, Rubber Ducky, etc.). (Citation: GitHub Pupy) [Pupy](https://attack.mitre.org/software/S0192) is publicly available on GitHub. (Citation: GitHub Pupy)",
					TechniquesUsed: []models.TechniqueUsed{
						{
							TechniqueID: "T1003",
							Name:        "T1003: OS Credential Dumping",
							Use:         "[Pupy](https://attack.mitre.org/software/S0192) can obtain a list of SIDs and provide the option for selecting process tokens to impersonate.(Citation: GitHub Pupy)",
						},
					},
					References: []models.AttackerReference{
						{
							Reference: models.Reference{
								SourceName:  "GitHub Pupy",
								Description: "Nicolas Verdier. (n.d.). Retrieved January 29, 2018.",
								URL:         "https://github.com/n1nj4sec/pupy",
							},
						},
					},
					Software: &models.AttackerSoftware{
						Type:                models.ToolType,
						AssociatedSoftwares: []models.AssociatedSoftware{},
						Platforms: []models.SoftwarePlatform{
							{Platform: "Linux"},
							{Platform: "Windows"},
							{Platform: "macOS"},
							{Platform: "Android"},
						},
						GroupsUsed: []models.GroupUsed{},
					},
					Created:  time.Date(2018, time.April, 18, 17, 59, 24, 739*int(time.Millisecond), time.UTC),
					Modified: time.Date(2020, time.May, 13, 22, 57, 00, 921*int(time.Millisecond), time.UTC),
				},
				{
					AttackerID:  "S0232",
					Type:        models.SoftwareType,
					Name:        "S0232: HOMEFRY",
					Description: "[HOMEFRY](https://attack.mitre.org/software/S0232) is a 64-bit Windows password dumper/cracker that has previously been used in conjunction with other [Leviathan](https://attack.mitre.org/groups/G0065) backdoors. (Citation: FireEye Periscope March 2018)",
					TechniquesUsed: []models.TechniqueUsed{
						{
							TechniqueID: "T1003",
							Name:        "T1003: OS Credential Dumping",
							Use:         "[HOMEFRY](https://attack.mitre.org/software/S0232) can perform credential dumping.(Citation: FireEye Periscope March 2018)",
						},
					},
					References: []models.AttackerReference{
						{
							Reference: models.Reference{
								SourceName:  "FireEye Periscope March 2018",
								Description: "FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.",
								URL:         "https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html",
							},
						},
						{
							Reference: models.Reference{
								SourceName:  "Symantec Buckeye",
								Description: "Symantec Security Response. (2016, September 6). Buckeye cyberespionage group shifts gaze from US to Hong Kong. Retrieved September 26, 2016.",
								URL:         "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong",
							},
						},
					},
					Software: &models.AttackerSoftware{
						Type: models.MalwareType,
						AssociatedSoftwares: []models.AssociatedSoftware{
							{
								Name:        "test",
								Description: "test",
							},
						},
						Platforms: []models.SoftwarePlatform{
							{Platform: "Windows"},
						},
						GroupsUsed: []models.GroupUsed{
							{
								Name:        "G0054: Sowbug",
								Description: "(Citation: Symantec Buckeye)",
							},
						},
					},
					Created:  time.Date(2018, time.April, 18, 17, 59, 24, 739*int(time.Millisecond), time.UTC),
					Modified: time.Date(2020, time.March, 30, 16, 47, 38, 393*int(time.Millisecond), time.UTC),
				},
				{
					AttackerID:  "C0010",
					Type:        models.CampaignType,
					Name:        "C0010: C0010",
					Description: "[C0010](https://attack.mitre.org/campaigns/C0010) was a cyber espionage campaign conducted by UNC3890 that targeted Israeli shipping, government, aviation, energy, and healthcare organizations. Security researcher assess UNC3890 conducts operations in support of Iranian interests, and noted several limited technical connections to Iran, including PDB strings and Farsi language artifacts. [C0010](https://attack.mitre.org/campaigns/C0010) began by at least late 2020, and was still ongoing as of mid-2022.(Citation: Mandiant UNC3890 Aug 2022)",
					TechniquesUsed: []models.TechniqueUsed{
						{
							TechniqueID: "T1003",
							Name:        "T1003: OS Credential Dumping",
							Use:         "For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors staged malware on their infrastructure for direct download onto a compromised system.(Citation: Mandiant UNC3890 Aug 2022) ",
						},
					},
					References: []models.AttackerReference{
						{
							Reference: models.Reference{
								SourceName:  "Mandiant UNC3890 Aug 2022",
								Description: "Mandiant Israel Research Team. (2022, August 17). Suspected Iranian Actor Targeting Israeli Shipping, Healthcare, Government and Energy Sectors. Retrieved September 21, 2022.",
								URL:         "https://www.mandiant.com/resources/blog/suspected-iranian-actor-targeting-israeli-shipping",
							},
						},
					},
					Created:  time.Date(2022, time.September, 21, 22, 16, 42, 3*int(time.Millisecond), time.UTC),
					Modified: time.Date(2022, time.October, 4, 20, 18, 28, 362*int(time.Millisecond), time.UTC),
				},
			},
		},
	}

	for i, tt := range tests {
		res, err := os.ReadFile(tt.in)
		if err != nil {
			t.Fatalf("[%d] Failed to read file. err: %s", i, err)
		}
		techniques, attackers, err := parse(res)
		if err != nil {
			if tt.wantErr {
				continue
			}
			t.Fatalf("[%d] Failed to parse. err: %s", i, err)
		}

		opts := []cmp.Option{
			cmpopts.SortSlices(func(i, j models.Technique) bool {
				return i.TechniqueID < j.TechniqueID
			}),
			cmpopts.SortSlices(func(i, j models.TechniqueReference) bool {
				return i.SourceName < j.SourceName
			}),
			cmpopts.SortSlices(func(i, j models.TechniquePlatform) bool {
				return i.Platform < j.Platform
			}),
			cmpopts.SortSlices(func(i, j models.Attacker) bool {
				return i.AttackerID < j.AttackerID
			}),
			cmpopts.SortSlices(func(i, j models.AttackerReference) bool {
				return i.SourceName < j.SourceName
			}),
		}
		if diff := cmp.Diff(techniques, tt.expectedTechniques, opts...); diff != "" {
			t.Errorf("[%d] parse techniques diff: (-got +want)\n%s", i, diff)
		}
		if diff := cmp.Diff(attackers, tt.expectedAttackers, opts...); diff != "" {
			t.Errorf("[%d] parse attackers diff: (-got +want)\n%s", i, diff)
		}
	}
}
