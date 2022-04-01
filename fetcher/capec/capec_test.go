package capec

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
			in: "testdata/stix-capec.json",
			expected: []models.Cti{
				{
					CtiID:       "CAPEC-1",
					Type:        models.CAPECType,
					Name:        "CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs",
					Description: "In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with the ability to access functionality not properly constrained by ACLs can obtain sensitive information and possibly compromise the entire application. Such an attacker can access resources that must be available only to users at a higher privilege level, can access management sections of the application, or can run queries for data that they otherwise not supposed to.",
					References:  []models.Reference{},
					Mitigations: []models.Mitigation{
						{
							Name:        "\n               <xhtml:p>In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as \"NoAccess\", with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user.</xhtml:p>\n               <xhtml:p>Having done so, any direct access to those protected Servlets will be prohibited by the web container.</xhtml:p>\n               <xhtml:p>In a more general setting, the administrator must mark every resource besides the ones supposed to be exposed to the user as accessible by a role impossible for the user to assume. The default security setting must be to deny access and then grant access only to those resources intended by business logic.</xhtml:p>\n            ",
							Description: "coa-1-0: \n               <xhtml:p>In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as \"NoAccess\", with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user.</xhtml:p>\n               <xhtml:p>Having done so, any direct access to those protected Servlets will be prohibited by the web container.</xhtml:p>\n               <xhtml:p>In a more general setting, the administrator must mark every resource besides the ones supposed to be exposed to the user as accessible by a role impossible for the user to assume. The default security setting must be to deny access and then grant access only to those resources intended by business logic.</xhtml:p>\n            ",
						},
					},
					MitreAttack: nil,
					Capec: &models.Capec{
						AttackIDs: []models.AttackID{
							{
								AttackID: "T1574.010",
							},
						},
						Status:             "Draft",
						TypicalSeverity:    "High",
						LikelihoodOfAttack: "High",
						Relationships: []models.Relationship{
							{
								Nature:   "ChildOf",
								Relation: "Meta: CAPEC-122: Privilege Abuse",
							},
							{
								Nature:   "ParentOf",
								Relation: "Detailed: CAPEC-58: Restful Privilege Elevation",
							},
							{
								Nature:   "CanFollow",
								Relation: "Standard: CAPEC-test: mock for test",
							},
							{
								Nature:   "CanPrecede",
								Relation: "Standard: CAPEC-17: Using Malicious Files",
							},
							{
								Nature:   "PeerOf",
								Relation: "Standard: CAPEC-test: mock for test",
							},
						},
						Domains:           "Hardware, Software",
						AlternateTerms:    "term1, term2",
						ExampleInstances:  "\n               <xhtml:p>Implementing the Model-View-Controller (MVC) within Java EE's Servlet paradigm using a \"Single front controller\" pattern that demands that brokered HTTP requests be authenticated before hand-offs to other Action Servlets.</xhtml:p>\n               <xhtml:p>If no security-constraint is placed on those Action Servlets, such that positively no one can access them, the front controller can be subverted.</xhtml:p>\n            ",
						Prerequisites:     "The application must be navigable in a manner that associates elements (subsections) of the application with ACLs., The various resources, or individual URLs, must be somehow discoverable by the attacker, The administrator must have forgotten to associate an ACL or has associated an inappropriately permissive ACL with a particular navigable resource.",
						ResourcesRequired: "None: No specialized resources are required to execute this type of attack.",
						SkillsRequired: []models.SkillRequired{
							{Skill: "Low: In order to discover unrestricted resources, the attacker does not need special tools or skills. They only have to observe the resources or access mechanisms invoked as each action is performed and then try and access those access mechanisms directly."},
						},
						Abstraction:   "Standard",
						ExecutionFlow: "<h2> Execution Flow </h2><div><h3>Explore</h3><ol><li> <p> <b>Survey: </b>The attacker surveys the target application, possibly as a valid and authenticated user</p></li><table><tbody><tr><th>Techniques</th></tr><tr><td>Spidering web sites for all available links</td></tr><tr><td>Brute force guessing of resource names</td></tr><tr><td>Brute force guessing of user names / credentials</td></tr><tr><td>Brute force guessing of function names / actions</td></tr></tbody></table><li> <p> <b>Identify Functionality: </b>At each step, the attacker notes the resource or functionality access mechanism invoked upon performing specific actions</p></li><table><tbody><tr><th>Techniques</th></tr><tr><td>Use the web inventory of all forms and inputs and apply attack data to those inputs.</td></tr><tr><td>Use a packet sniffer to capture and record network traffic</td></tr><tr><td>Execute the software in a debugger and record API calls into the operating system or important libraries. This might occur in an environment other than a production environment, in order to find weaknesses that can be exploited in a production environment.</td></tr></tbody></table></ol></div><div><h3>Experiment</h3><ol><li> <p> <b>Iterate over access capabilities: </b>Possibly as a valid user, the attacker then tries to access each of the noted access mechanisms directly in order to perform functions not constrained by the ACLs.</p></li><table><tbody><tr><th>Techniques</th></tr><tr><td>Fuzzing of API parameters (URL parameters, OS API parameters, protocol parameters)</td></tr></tbody></table></ol></div>",
						Consequences: []models.Consequence{
							{Consequence: "Access_Control: Gain Privileges"},
							{Consequence: "Authorization: Gain Privileges"},
							{Consequence: "Confidentiality: Gain Privileges"},
						},
						RelatedWeaknesses: []models.RelatedWeakness{
							{CweID: "CWE-276"},
							{CweID: "CWE-285"},
							{CweID: "CWE-434"},
							{CweID: "CWE-693"},
							{CweID: "CWE-732"},
							{CweID: "CWE-1193"},
							{CweID: "CWE-1220"},
							{CweID: "CWE-1297"},
							{CweID: "CWE-1311"},
							{CweID: "CWE-1314"},
							{CweID: "CWE-1315"},
							{CweID: "CWE-1318"},
							{CweID: "CWE-1320"},
							{CweID: "CWE-1321"},
							{CweID: "CWE-1327"},
						},
					},
					Created:  time.Date(2014, time.June, 23, 0, 0, 0, 0, time.UTC),
					Modified: time.Date(2021, time.October, 21, 0, 0, 0, 0, time.UTC),
				},
				{
					CtiID:       "CAPEC-122",
					Type:        models.CAPECType,
					Name:        "CAPEC-122: Privilege Abuse",
					Description: "An adversary is able to exploit features of the target that should be reserved for privileged users or administrators but are exposed to use by lower or non-privileged accounts. Access to sensitive information and functionality must be controlled to ensure that only authorized users are able to access these resources.",
					References:  []models.Reference{},
					Mitigations: []models.Mitigation{},
					MitreAttack: nil,
					Capec: &models.Capec{
						AttackIDs:           []models.AttackID{},
						Status:              "Draft",
						ExtendedDescription: "\n            <xhtml:p>If access control mechanisms are absent or misconfigured, a user may be able to access resources that are intended only for higher level users. An adversary may be able to exploit this to utilize a less trusted account to gain information and perform activities reserved for more trusted accounts.</xhtml:p>\n            <xhtml:p>This attack differs from privilege escalation and other privilege stealing attacks in that the adversary never actually escalates their privileges but instead is able to use a lesser degree of privilege to access resources that should be (but are not) reserved for higher privilege accounts. Likewise, the adversary does not exploit trust or subvert systems - all control functionality is working as configured but the configuration does not adequately protect sensitive resources at an appropriate level.</xhtml:p>\n         ",
						TypicalSeverity:     "Medium",
						LikelihoodOfAttack:  "High",
						Relationships:       []models.Relationship{},
						Domains:             "Hardware, Software",
						ExampleInstances:    "\n               <xhtml:p>Improperly configured account privileges allowed unauthorized users on a hospital's network to access the medical records for over 3,000 patients. Thus compromising data integrity and confidentiality in addition to HIPAA violations.</xhtml:p>\n            ",
						Prerequisites:       "The target must have misconfigured their access control mechanisms such that sensitive information, which should only be accessible to more trusted users, remains accessible to less trusted users., The adversary must have access to the target, albeit with an account that is less privileged than would be appropriate for the targeted resources.",
						ResourcesRequired:   "None: No specialized resources are required to execute this type of attack. The ability to access the target is required.",
						SkillsRequired: []models.SkillRequired{
							{Skill: "Low: Adversary can leverage privileged features they already have access to without additional effort or skill. Adversary is only required to have access to an account with improper priveleges."},
						},
						Abstraction: "Meta",
						Consequences: []models.Consequence{
							{Consequence: "Access_Control: Bypass Protection Mechanism"},
							{Consequence: "Authorization: Bypass Protection Mechanism"},
							{Consequence: "Authorization: Execute Unauthorized Commands (Run Arbitrary Code)"},
							{Consequence: "Authorization: Gain Privileges"},
							{Consequence: "Confidentiality: Read Data"},
							{Consequence: "Integrity: Modify Data"},
						},
						RelatedWeaknesses: []models.RelatedWeakness{
							{CweID: "CWE-269"},
							{CweID: "CWE-732"},
							{CweID: "CWE-1317"},
						},
					},
					Created:  time.Date(2014, time.June, 23, 0, 0, 0, 0, time.UTC),
					Modified: time.Date(2022, time.February, 22, 0, 0, 0, 0, time.UTC),
				},
				{
					CtiID:       "CAPEC-17",
					Type:        models.CAPECType,
					Name:        "CAPEC-17: Using Malicious Files",
					Description: "An attack of this type exploits a system's configuration that allows an adversary to either directly access an executable file, for example through shell access; or in a possible worst case allows an adversary to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the programmers and the administrators must be in synch regarding the interfaces and the correct privileges for each interface.",
					References: []models.Reference{
						{
							SourceName:  "reference_from_CAPEC",
							Description: "G. Hoglund, G. McGraw, Exploiting Software: How to Break Code, 2004--02, Addison-Wesley",
						},
					},
					Mitigations: []models.Mitigation{},
					MitreAttack: nil,
					Capec: &models.Capec{
						AttackIDs: []models.AttackID{
							{AttackID: "T1574.010"},
						},
						Status:             "Draft",
						TypicalSeverity:    "Very High",
						LikelihoodOfAttack: "High",
						Relationships:      []models.Relationship{},
						Domains:            "Hardware, Software",
						ExampleInstances:   "\n               <xhtml:p>Consider a directory on a web server with the following permissions</xhtml:p>\n               <xhtml:div style=\"margin-left:10px;\" class=\"informative\">drwxrwxrwx 5 admin public 170 Nov 17 01:08 webroot</xhtml:div>\n               <xhtml:p>This could allow an attacker to both execute and upload and execute programs' on the web server. This one vulnerability can be exploited by a threat to probe the system and identify additional vulnerabilities to exploit.</xhtml:p>\n            ",
						Prerequisites:      "System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications between the subject and the object is set incorrectly or assumes a benign environment.",
						ResourcesRequired:  "Ability to communicate synchronously or asynchronously with server that publishes an over-privileged directory, program, or interface. Optionally, ability to capture output directly through synchronous communication or other method such as FTP.",
						SkillsRequired: []models.SkillRequired{
							{Skill: "Low: To identify and execute against an over-privileged system interface"},
						},
						Abstraction:   "Standard",
						ExecutionFlow: "<h2> Execution Flow </h2><div><h3>Explore</h3><ol><li> <p> <b>Determine File/Directory Configuration: </b>The adversary looks for misconfigured files or directories on a system that might give executable access to an overly broad group of users.</p></li><table><tbody><tr><th>Techniques</th></tr><tr><td>Through shell access to a system, use the command \"ls -l\" to view permissions for files and directories.</td></tr></tbody></table></ol></div><div><h3>Experiment</h3><ol><li> <p> <b>Upload Malicious Files: </b>If the adversary discovers a directory that has executable permissions, they will attempt to upload a malicious file to execute.</p></li><table><tbody><tr><th>Techniques</th></tr><tr><td>Upload a malicious file through a misconfigured FTP server.</td></tr></tbody></table></ol></div><div><h3>Exploit</h3><ol><li> <p> <b>Execute Malicious File: </b>The adversary either executes the uploaded malicious file, or executes an existing file that has been misconfigured to allow executable access to the adversary.</p></li></ol></div>",
						Consequences: []models.Consequence{
							{Consequence: "Access_Control: Gain Privileges"},
							{Consequence: "Authorization: Gain Privileges"},
							{Consequence: "Availability: Execute Unauthorized Commands (Run Arbitrary Code)"},
							{Consequence: "Confidentiality: Execute Unauthorized Commands (Run Arbitrary Code)"},
							{Consequence: "Confidentiality: Gain Privileges"},
							{Consequence: "Confidentiality: Read Data"},
							{Consequence: "Integrity: Execute Unauthorized Commands (Run Arbitrary Code)"},
							{Consequence: "Integrity: Modify Data"},
						},
						RelatedWeaknesses: []models.RelatedWeakness{
							{CweID: "CWE-732"},
							{CweID: "CWE-285"},
							{CweID: "CWE-272"},
							{CweID: "CWE-59"},
							{CweID: "CWE-282"},
							{CweID: "CWE-270"},
							{CweID: "CWE-693"},
						},
					},
					Created:  time.Date(2014, time.June, 23, 0, 0, 0, 0, time.UTC),
					Modified: time.Date(2022, time.February, 22, 0, 0, 0, 0, time.UTC),
				},
				{
					CtiID:       "CAPEC-58",
					Type:        models.CAPECType,
					Name:        "CAPEC-58: Restful Privilege Elevation",
					Description: "Rest uses standard HTTP (Get, Put, Delete) style permissions methods, but these are not necessarily correlated generally with back end programs. Strict interpretation of HTTP get methods means that these HTTP Get services should not be used to delete information on the server, but there is no access control mechanism to back up this logic. This means that unless the services are properly ACL'd and the application's service implementation are following these guidelines then an HTTP request can easily execute a delete or update on the server side. The attacker identifies a HTTP Get URL such as http://victimsite/updateOrder, which calls out to a program to update orders on a database or other resource. The URL is not idempotent so the request can be submitted multiple times by the attacker, additionally, the attacker may be able to exploit the URL published as a Get method that actually performs updates (instead of merely retrieving data). This may result in malicious or inadvertent altering of data on the server.",
					References: []models.Reference{
						{
							SourceName:  "reference_from_CAPEC",
							Description: "Mark O'Neill, Security for REST Web Services, Vprde;",
							URL:         "http://www.vordel.com/downloads/rsa_conf_2006.pdf",
						},
					},
					Mitigations: []models.Mitigation{},
					MitreAttack: nil,
					Capec: &models.Capec{
						AttackIDs:          []models.AttackID{},
						Status:             "Draft",
						TypicalSeverity:    "High",
						LikelihoodOfAttack: "High",
						Relationships:      []models.Relationship{},
						Domains:            "Hardware, Software",
						ExampleInstances:   "The HTTP Get method is designed to retrieve resources and not to alter the state of the application or resources on the server side. However, developers can easily code programs that accept a HTTP Get request that do in fact create, update or delete data on the server. Both Flickr (http://www.flickr.com/services/api/flickr.photosets.delete.html) and del.icio.us (http://del.icio.us/api/posts/delete) have implemented delete operations using standard HTTP Get requests. These HTTP Get methods do delete data on the server side, despite being called from Get which is not supposed to alter state.",
						Prerequisites:      "The attacker needs to be able to identify HTTP Get URLs. The Get methods must be set to call applications that perform operations other than get such as update and delete.",
						SkillsRequired: []models.SkillRequired{
							{Skill: "Low: It is relatively straightforward to identify an HTTP Get method that changes state on the server side and executes against an over-privileged system interface"},
						},
						Abstraction: "Detailed",
						Consequences: []models.Consequence{
							{Consequence: "Access_Control: Gain Privileges"},
							{Consequence: "Authorization: Gain Privileges"},
							{Consequence: "Confidentiality: Gain Privileges"},
							{Consequence: "Integrity: Modify Data"},
						},
						RelatedWeaknesses: []models.RelatedWeakness{
							{CweID: "CWE-267"},
							{CweID: "CWE-269"},
						},
					},
					Created:  time.Date(2014, time.June, 23, 0, 0, 0, 0, time.UTC),
					Modified: time.Date(2021, time.June, 24, 0, 0, 0, 0, time.UTC),
				},
				{
					CtiID:       "CAPEC-test",
					Type:        models.CAPECType,
					Name:        "CAPEC-test: mock for test",
					Description: "",
					References:  []models.Reference{},
					Mitigations: []models.Mitigation{},
					MitreAttack: nil,
					Capec: &models.Capec{
						AttackIDs:           []models.AttackID{},
						Status:              "",
						ExtendedDescription: "",
						TypicalSeverity:     "",
						LikelihoodOfAttack:  "",
						Relationships:       []models.Relationship{},
						Domains:             "",
						ExampleInstances:    "",
						Prerequisites:       "",
						ResourcesRequired:   "",
						SkillsRequired:      []models.SkillRequired{},
						Abstraction:         "Standard",
						Consequences:        []models.Consequence{},
						RelatedWeaknesses:   []models.RelatedWeakness{},
					},
					Created:  time.Date(2014, time.June, 23, 0, 0, 0, 0, time.UTC),
					Modified: time.Date(2019, time.September, 30, 0, 0, 0, 0, time.UTC),
				},
			},
		},
		{
			in:       "testdata/deprecated.json",
			expected: []models.Cti{},
		},
		{
			in:      "testdata/fail_expand.json",
			wantErr: true,
		},
		{
			in:      "testdata/fail_get_addinfo.json",
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
			cmpopts.SortSlices(func(i, j models.Consequence) bool {
				return i.Consequence < j.Consequence
			}),
		}
		if diff := cmp.Diff(actual, tt.expected, opts...); diff != "" {
			t.Errorf("[%d] parse diff: (-got +want)\n%s", i, diff)
		}
	}
}
