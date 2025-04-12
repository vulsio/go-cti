package attack

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

const attackURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// Fetch MITRE ATT&CK data
func Fetch() ([]models.Technique, []models.Attacker, error) {
	log15.Info("Fetching MITRE ATT&CK...")

	res, err := utils.FetchURL(attackURL)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to fetch MITRE ATT&CK JSON. err: %w", err)
	}
	techniques, attackers, err := parse(res)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to parse MITRE ATT&CK Cyber Threat Intelligence. err: %w", err)
	}
	return techniques, attackers, nil
}

func parse(res []byte) ([]models.Technique, []models.Attacker, error) {
	var r root
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
	}

	attackPatterns, attackers, others, relationships, err := parseEachObject(r.Objects)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to parseEachObject. err: %w", err)
	}

	techniques := []models.Technique{}
	for id, attackPattern := range attackPatterns {
		if attackPattern.deprecated {
			continue
		}
		technique, err := fillTechnique(attackPattern, relationships[id], attackPatterns, attackers, others)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to fillTechnique. err: %w", err)
		}
		techniques = append(techniques, technique)
	}

	techniquesUsed := map[string][]techniqueUsed{}
	for _, rels := range relationships {
		for _, rel := range rels {
			if !strings.HasPrefix(rel.targetRef, "attack-pattern--") || !strings.HasPrefix(rel.sourceRef, "intrusion-set--") && !strings.HasPrefix(rel.sourceRef, "malware--") && !strings.HasPrefix(rel.sourceRef, "tool--") && !strings.HasPrefix(rel.sourceRef, "campaign--") {
				continue
			}
			technique, ok := attackPatterns[rel.targetRef]
			if !ok {
				return nil, nil, xerrors.Errorf("Failed to get Technique. rel.id: %s, rel.targetRef: %s", rel.id, rel.targetRef)
			}
			techniquesUsed[rel.sourceRef] = append(techniquesUsed[rel.sourceRef], techniqueUsed{
				id:         technique.id,
				name:       technique.name,
				use:        rel.description,
				references: rel.references,
			})
		}
	}

	groupsUsed := map[string][]groupUsed{}
	for _, rels := range relationships {
		for _, rel := range rels {
			if !strings.HasPrefix(rel.targetRef, "malware--") && !strings.HasPrefix(rel.targetRef, "tool--") || !strings.HasPrefix(rel.sourceRef, "intrusion-set--") {
				continue
			}
			software, ok := attackers[rel.targetRef]
			if !ok {
				return nil, nil, xerrors.Errorf("Failed to get Attacker Software. rel.id: %s, rel.targetRef: %s", rel.id, rel.targetRef)
			}
			groupsUsed[rel.sourceRef] = append(groupsUsed[rel.sourceRef], groupUsed{
				name:        software.name,
				description: rel.description,
				references:  rel.references,
			})
		}
	}

	attackerInfos := []models.Attacker{}
	for id, attacker := range attackers {
		if attacker.deprecated {
			continue
		}
		attackerInfo, err := fillAttacker(attacker, relationships[id], attackers, techniquesUsed[id], groupsUsed[id])
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to fillAttacker. err: %w", err)
		}
		attackerInfos = append(attackerInfos, attackerInfo)
	}

	return techniques, attackerInfos, nil
}

func parseEachObject(root []ctiObject) (map[string]attackPattern, map[string]attacker, map[string]otherInfo, map[string][]relationship, error) {
	attackPatterns := map[string]attackPattern{}
	attackers := map[string]attacker{}
	others := map[string]otherInfo{}
	dataSources := map[string]string{}
	dataComponents := map[string]dataComponent{}
	relationships := map[string][]relationship{}
	for _, obj := range root {
		switch obj.Type {
		case "attack-pattern":
			attackPatterns[obj.ID] = parseAttackPattern(obj)
		case "course-of-action":
			others[obj.ID] = otherInfo{
				objType:     obj.Type,
				name:        getObjectName(obj.Name, obj.ExternalReferences),
				description: obj.Description,
				deprecated:  obj.Revoked || obj.XMitreDeprecated,
			}
		case "intrusion-set", "malware", "tool", "campaign":
			attackers[obj.ID] = parseAttacker(obj)
		case "x-mitre-tactic":
			others[obj.XMitreShortname] = otherInfo{
				objType:     obj.Type,
				name:        getObjectName(obj.Name, obj.ExternalReferences),
				description: obj.Description,
			}
		case "x-mitre-data-source":
			dataSources[obj.ID] = getObjectName(obj.Name, obj.ExternalReferences)
		case "x-mitre-data-component":
			dataComponents[obj.ID] = dataComponent{
				name:          obj.Name,
				description:   obj.Description,
				dataSourceRef: obj.XMitreDataSourceRef,
			}
		case "relationship":
			relationships[obj.TargetRef] = append(relationships[obj.TargetRef], relationship{
				id:               obj.ID,
				description:      obj.Description,
				relationshipType: obj.RelationshipType,
				sourceRef:        obj.SourceRef,
				targetRef:        obj.TargetRef,
				references:       obj.ExternalReferences,
			})
		}
	}

	for id, component := range dataComponents {
		ds, ok := dataSources[component.dataSourceRef]
		if !ok {
			return nil, nil, nil, nil, xerrors.Errorf("Failed to get data source name. id: %s, err: broken relationships", id)
		}
		others[id] = otherInfo{
			objType:     "x-mitre-data-component",
			name:        fmt.Sprintf("%s: %s", ds, component.name),
			description: component.description,
		}
	}

	return attackPatterns, attackers, others, relationships, nil
}

func parseAttackPattern(obj ctiObject) attackPattern {
	r := attackPattern{
		name:                 obj.Name,
		description:          obj.Description,
		permissionRequired:   obj.XMitrePermissionsRequired,
		effectivePermissions: obj.XMitreEffectivePermissions,
		platforms:            obj.XMitrePlatforms,
		impactType:           obj.XMitreImpactType,
		networkRequirements:  obj.XMitreNetworkRequirements,
		remoteSupport:        obj.XMitreRemoteSupport,
		defenseByPassed:      obj.XMitreDefenseBypassed,
		detection:            obj.XMitreDetection,
		created:              obj.Created,
		modified:             obj.Modified,
		deprecated:           obj.Revoked || obj.XMitreDeprecated,
	}

	for _, ref := range obj.ExternalReferences {
		switch ref.SourceName {
		case "mitre-attack":
			r.id = ref.ExternalID
			r.name = fmt.Sprintf("%s: %s", ref.ExternalID, obj.Name)
		case "capec":
			r.capecIDs = append(r.capecIDs, ref.ExternalID)
		default:
			r.references = append(r.references, ref)
		}
	}

	for _, phase := range obj.KillChainPhases {
		r.killChainPhases = append(r.killChainPhases, phase.PhaseName)
	}

	return r
}

func parseAttacker(obj ctiObject) attacker {
	r := attacker{
		objType:     obj.Type,
		name:        obj.Name,
		description: obj.Description,
		platforms:   obj.XMitrePlatforms,
		created:     obj.Created,
		modified:    obj.Modified,
		deprecated:  obj.Revoked || obj.XMitreDeprecated,
	}

	for _, ref := range obj.ExternalReferences {
		switch ref.SourceName {
		case "mitre-attack":
			r.id = ref.ExternalID
			r.name = fmt.Sprintf("%s: %s", ref.ExternalID, obj.Name)
		default:
			r.references = append(r.references, ref)
		}
	}

	switch obj.Type {
	case "intrusion-set", "campaign":
		r.aliases = append(r.aliases, obj.Aliases...)
	case "malware", "tool":
		r.aliases = append(r.aliases, obj.XMitreAliases...)
	}

	return r
}

func getObjectName(objName string, refs []reference) string {
	for _, ref := range refs {
		if ref.SourceName == "mitre-attack" {
			return fmt.Sprintf("%s: %s", ref.ExternalID, objName)
		}
	}
	return objName
}

func fillTechnique(attackPattern attackPattern, relationships []relationship, attackPatterns map[string]attackPattern, attackers map[string]attacker, others map[string]otherInfo) (models.Technique, error) {
	technique := models.Technique{
		TechniqueID: attackPattern.id,
		Type:        models.MitreAttackType,
		Name:        attackPattern.name,
		Description: attackPattern.description,
		References:  []models.TechniqueReference{},
		Mitigations: []models.Mitigation{},
		MitreAttack: &models.MitreAttack{
			CapecIDs:             []models.CapecID{},
			Detection:            attackPattern.detection,
			KillChainPhases:      []models.KillChainPhase{},
			DataSources:          []models.DataSource{},
			Procedures:           []models.Procedure{},
			Platforms:            []models.TechniquePlatform{},
			PermissionsRequired:  []models.PermissionRequired{},
			EffectivePermissions: []models.EffectivePermission{},
			DefenseBypassed:      []models.DefenseBypassed{},
			ImpactType:           []models.ImpactType{},
			NetworkRequirements:  attackPattern.networkRequirements,
			RemoteSupport:        attackPattern.remoteSupport,
			SubTechniques:        []models.SubTechnique{},
		},
		Created:  attackPattern.created,
		Modified: attackPattern.modified,
	}

	for _, capecID := range attackPattern.capecIDs {
		technique.MitreAttack.CapecIDs = append(technique.MitreAttack.CapecIDs, models.CapecID{
			CapecID: capecID,
		})
	}

	references := map[string]models.TechniqueReference{}
	for _, ref := range attackPattern.references {
		references[ref.SourceName] = models.TechniqueReference{
			Reference: models.Reference{
				SourceName:  ref.SourceName,
				Description: ref.Description,
				URL:         ref.URL,
			},
		}
	}

	for _, rel := range relationships {
		if rel.relationshipType == "revoked-by" {
			continue
		}

		for _, ref := range rel.references {
			references[ref.SourceName] = models.TechniqueReference{
				Reference: models.Reference{
					SourceName:  ref.SourceName,
					Description: ref.Description,
					URL:         ref.URL,
				},
			}
		}

		switch objType := strings.Split(rel.sourceRef, "--")[0]; objType {
		case "attack-pattern":
			info, ok := attackPatterns[rel.sourceRef]
			if !ok {
				return models.Technique{}, xerrors.Errorf("Failed to get attack-pattern. relationship id: %s, err: broken relationships. does not exists source ref: %s", rel.id, rel.sourceRef)
			}
			if info.deprecated {
				continue
			}
			technique.MitreAttack.SubTechniques = append(technique.MitreAttack.SubTechniques, models.SubTechnique{
				Name: info.name,
			})
		case "course-of-action":
			info, ok := others[rel.sourceRef]
			if !ok {
				return models.Technique{}, xerrors.Errorf("Failed to get course-of-action. relationship id: %s, err: broken relationships. does not exists source ref: %s", rel.id, rel.sourceRef)
			}
			if info.deprecated {
				continue
			}
			technique.Mitigations = append(technique.Mitigations, models.Mitigation{
				Name:        info.name,
				Description: info.description,
			})
		case "intrusion-set", "malware", "tool", "campaign":
			info, ok := attackers[rel.sourceRef]
			if !ok {
				return models.Technique{}, xerrors.Errorf("Failed to get attacker. relationship id: %s, err: broken relationships. does not exists source ref: %s", rel.id, rel.sourceRef)
			}
			if info.deprecated {
				continue
			}
			technique.MitreAttack.Procedures = append(technique.MitreAttack.Procedures, models.Procedure{
				Name:        info.name,
				Description: info.description,
			})
		case "x-mitre-data-component":
			info, ok := others[rel.sourceRef]
			if !ok {
				return models.Technique{}, xerrors.Errorf("Failed to get data-component. relationship id: %s, err: broken relationships. does not exists source ref: %s", rel.id, rel.sourceRef)
			}
			if info.deprecated {
				continue
			}
			technique.MitreAttack.DataSources = append(technique.MitreAttack.DataSources, models.DataSource{
				Name:        info.name,
				Description: info.description,
			})
		}
	}

	for _, phase := range attackPattern.killChainPhases {
		info, ok := others[phase]
		if !ok {
			return models.Technique{}, xerrors.Errorf("Failed to get kill chain phase name. phase_name(x_mitre_shortname): %s, err: broken relationships", phase)
		}
		technique.MitreAttack.KillChainPhases = append(technique.MitreAttack.KillChainPhases, models.KillChainPhase{Tactic: info.name})
	}

	for _, platform := range attackPattern.platforms {
		technique.MitreAttack.Platforms = append(technique.MitreAttack.Platforms, models.TechniquePlatform{
			Platform: platform,
		})
	}

	for _, permission := range attackPattern.permissionRequired {
		technique.MitreAttack.PermissionsRequired = append(technique.MitreAttack.PermissionsRequired, models.PermissionRequired{
			Permission: permission,
		})
	}

	for _, permission := range attackPattern.effectivePermissions {
		technique.MitreAttack.EffectivePermissions = append(technique.MitreAttack.EffectivePermissions, models.EffectivePermission{
			Permission: permission,
		})
	}

	for _, defense := range attackPattern.defenseByPassed {
		technique.MitreAttack.DefenseBypassed = append(technique.MitreAttack.DefenseBypassed, models.DefenseBypassed{
			Defense: defense,
		})
	}

	for _, impactType := range attackPattern.impactType {
		technique.MitreAttack.ImpactType = append(technique.MitreAttack.ImpactType, models.ImpactType{
			Type: impactType,
		})
	}

	for _, ref := range references {
		technique.References = append(technique.References, ref)
	}

	return technique, nil
}

func fillAttacker(attacker attacker, relationships []relationship, attackers map[string]attacker, techniquesUsed []techniqueUsed, groupsUsed []groupUsed) (models.Attacker, error) {
	attackerInfo := models.Attacker{
		AttackerID:     attacker.id,
		Name:           attacker.name,
		Description:    attacker.description,
		TechniquesUsed: []models.TechniqueUsed{},
		References:     []models.AttackerReference{},
		Created:        attacker.created,
		Modified:       attacker.modified,
	}

	references := map[string]models.AttackerReference{}
	switch attacker.objType {
	case "intrusion-set":
		attackerInfo.Type = models.GroupType
		attackerInfo.Group = &models.AttackerGroup{
			AssociatedGroups: []models.AssociatedGroup{},
			SoftwaresUsed:    []models.SoftwareUsed{},
		}
		for _, alias := range attacker.aliases {
			if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, alias) != attackerInfo.Name {
				attackerInfo.Group.AssociatedGroups = append(attackerInfo.Group.AssociatedGroups, models.AssociatedGroup{
					Name: alias,
				})
			}
		}
		for _, ref := range attacker.references {
			found := false
			for i := range attackerInfo.Group.AssociatedGroups {
				if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, ref.SourceName) == attackerInfo.Name {
					found = true
					break
				}
				if ref.SourceName == attackerInfo.Group.AssociatedGroups[i].Name {
					attackerInfo.Group.AssociatedGroups[i].Description = ref.Description
					found = true
					break
				}
			}
			if !found {
				references[ref.SourceName] = models.AttackerReference{
					Reference: models.Reference{
						SourceName:  ref.SourceName,
						Description: ref.Description,
						URL:         ref.URL,
					},
				}
			}
		}
		for _, groupUsed := range groupsUsed {
			attackerInfo.Group.SoftwaresUsed = append(attackerInfo.Group.SoftwaresUsed, models.SoftwareUsed{
				Name:        groupUsed.name,
				Description: groupUsed.description,
			})
			for _, ref := range groupUsed.references {
				references[ref.SourceName] = models.AttackerReference{
					Reference: models.Reference{
						SourceName:  ref.SourceName,
						Description: ref.Description,
						URL:         ref.URL,
					},
				}
			}
		}
	case "malware":
		attackerInfo.Type = models.SoftwareType
		attackerInfo.Software = &models.AttackerSoftware{
			Type:                models.MalwareType,
			AssociatedSoftwares: []models.AssociatedSoftware{},
			Platforms:           []models.SoftwarePlatform{},
			GroupsUsed:          []models.GroupUsed{},
		}
		for _, alias := range attacker.aliases {
			if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, alias) != attackerInfo.Name {
				attackerInfo.Software.AssociatedSoftwares = append(attackerInfo.Software.AssociatedSoftwares, models.AssociatedSoftware{
					Name: alias,
				})
			}
		}
		for _, platform := range attacker.platforms {
			attackerInfo.Software.Platforms = append(attackerInfo.Software.Platforms, models.SoftwarePlatform{
				Platform: platform,
			})
		}
		for _, ref := range attacker.references {
			found := false
			for i := range attackerInfo.Software.AssociatedSoftwares {
				if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, ref.SourceName) == attackerInfo.Name {
					found = true
					break
				}
				if ref.SourceName == attackerInfo.Software.AssociatedSoftwares[i].Name {
					attackerInfo.Software.AssociatedSoftwares[i].Description = ref.Description
					found = true
					break
				}
			}
			if !found {
				references[ref.SourceName] = models.AttackerReference{
					Reference: models.Reference{
						SourceName:  ref.SourceName,
						Description: ref.Description,
						URL:         ref.URL,
					},
				}
			}
		}
	case "tool":
		attackerInfo.Type = models.SoftwareType
		attackerInfo.Software = &models.AttackerSoftware{
			Type:                models.ToolType,
			AssociatedSoftwares: []models.AssociatedSoftware{},
			Platforms:           []models.SoftwarePlatform{},
			GroupsUsed:          []models.GroupUsed{},
		}
		for _, alias := range attacker.aliases {
			if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, alias) != attackerInfo.Name {
				attackerInfo.Software.AssociatedSoftwares = append(attackerInfo.Software.AssociatedSoftwares, models.AssociatedSoftware{
					Name: alias,
				})
			}
		}
		for _, platform := range attacker.platforms {
			attackerInfo.Software.Platforms = append(attackerInfo.Software.Platforms, models.SoftwarePlatform{
				Platform: platform,
			})
		}
		for _, ref := range attacker.references {
			found := false
			for i := range attackerInfo.Software.AssociatedSoftwares {
				if fmt.Sprintf("%s: %s", attackerInfo.AttackerID, ref.SourceName) == attackerInfo.Name {
					found = true
					break
				}
				if ref.SourceName == attackerInfo.Software.AssociatedSoftwares[i].Name {
					attackerInfo.Software.AssociatedSoftwares[i].Description = ref.Description
					found = true
					break
				}
			}
			if !found {
				references[ref.SourceName] = models.AttackerReference{
					Reference: models.Reference{
						SourceName:  ref.SourceName,
						Description: ref.Description,
						URL:         ref.URL,
					},
				}
			}
		}
	case "campaign":
		attackerInfo.Type = models.CampaignType
		// attackerInfo.Campaign = &models.AttackerCampaign{
		// 	Softwares: []models.AttackerCampaignSoftware{},
		// 	Groups:    []models.AttackerCampaignGroup{},
		// }
	}

	for _, techniqueUsed := range techniquesUsed {
		attackerInfo.TechniquesUsed = append(attackerInfo.TechniquesUsed, models.TechniqueUsed{
			TechniqueID: techniqueUsed.id,
			Name:        techniqueUsed.name,
			Use:         techniqueUsed.use,
		})

		for _, ref := range techniqueUsed.references {
			references[ref.SourceName] = models.AttackerReference{
				Reference: models.Reference{
					SourceName:  ref.SourceName,
					Description: ref.Description,
					URL:         ref.URL,
				},
			}
		}
	}

	for _, rel := range relationships {
		if rel.relationshipType == "revoked-by" {
			continue
		}

		for _, ref := range rel.references {
			references[ref.SourceName] = models.AttackerReference{
				Reference: models.Reference{
					SourceName:  ref.SourceName,
					Description: ref.Description,
					URL:         ref.URL,
				},
			}
		}

		attackerUsed, ok := attackers[rel.sourceRef]
		if !ok {
			return models.Attacker{}, xerrors.Errorf("Failed to get attacker used. rel.id: %s, rel.sourceRef: %s", rel.id, rel.sourceRef)
		}
		if attackerUsed.deprecated {
			continue
		}

		if attackerUsed.objType == "intrusion-set" {
			attackerInfo.Software.GroupsUsed = append(attackerInfo.Software.GroupsUsed, models.GroupUsed{
				Name:        attackerUsed.name,
				Description: rel.description,
			})
		}
	}

	for _, ref := range references {
		attackerInfo.References = append(attackerInfo.References, ref)
	}

	return attackerInfo, nil
}
