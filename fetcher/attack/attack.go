package attack

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

const attackURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

func Fetch() ([]models.Cti, error) {
	log15.Info("Fetching MITRE ATT&CK...")

	res, err := utils.FetchURL(attackURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch MITRE ATT&CK JSON. err: %w", err)
	}
	ctis, err := parse(res)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse MITRE ATT&CK Cyber Threat Intelligence. err: %w", err)
	}
	return ctis, nil
}

func parse(res []byte) ([]models.Cti, error) {
	var r root
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
	}

	attackPatterns := map[string]attackPattern{}
	additionalInfos := map[string]additionalInfoObject{}
	dataSources := map[string]string{}
	dataComponents := map[string]dataComponent{}
	relationships := map[string][]relationshipObject{}
	for _, obj := range r.Objects {
		switch obj.Type {
		case "attack-pattern":
			attackPatterns[obj.ID] = parseAttackPattern(obj)
			additionalInfos[obj.ID] = additionalInfoObject{
				objType:     obj.Type,
				name:        attackPatterns[obj.ID].name,
				description: attackPatterns[obj.ID].description,
				deprecated:  obj.Revoked || obj.XMitreDeprecated,
			}
		case "course-of-action", "intrusion-set", "malware", "tool":
			additionalInfos[obj.ID] = additionalInfoObject{
				objType:     obj.Type,
				name:        getObjectName(obj.Name, obj.ExternalReferences),
				description: obj.Description,
				deprecated:  obj.Revoked || obj.XMitreDeprecated,
			}
		case "x-mitre-tactic":
			additionalInfos[obj.XMitreShortname] = additionalInfoObject{
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
			if !strings.HasPrefix(obj.TargetRef, "attack-pattern--") {
				continue
			}
			relationships[obj.TargetRef] = append(relationships[obj.TargetRef], relationshipObject{
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
			return nil, xerrors.Errorf("Failed to get data source name. id: %s, err: broken relationships", id)
		}
		additionalInfos[id] = additionalInfoObject{
			objType:     "x-mitre-data-component",
			name:        fmt.Sprintf("%s: %s", ds, component.name),
			description: component.description,
		}
	}

	ctis := []models.Cti{}
	for id, attackPattern := range attackPatterns {
		if attackPattern.deprecated {
			continue
		}

		cti := models.Cti{
			CtiID:       attackPattern.id,
			Type:        models.MitreAttackType,
			Name:        attackPattern.name,
			Description: attackPattern.description,
			References:  []models.Reference{},
			Mitigations: []models.Mitigation{},
			MitreAttack: &models.MitreAttack{
				CapecIDs:             []models.CapecID{},
				Detection:            attackPattern.detection,
				DataSources:          []models.DataSource{},
				Procedures:           []models.Procedure{},
				Platforms:            attackPattern.platforms,
				PermissionsRequired:  attackPattern.permissionRequired,
				EffectivePermissions: attackPattern.effectivePermissions,
				DefenseBypassed:      attackPattern.defenseByPassed,
				ImpactType:           attackPattern.impactType,
				NetworkRequirements:  attackPattern.networkRequirements,
				RemoteSupport:        attackPattern.remoteSupport,
				SubTechniques:        []models.SubTechnique{},
			},
			Created:  attackPattern.created,
			Modified: attackPattern.modified,
		}

		for _, capecID := range attackPattern.capecIDs {
			cti.MitreAttack.CapecIDs = append(cti.MitreAttack.CapecIDs, models.CapecID{
				CapecID: capecID,
			})
		}

		for _, ref := range attackPattern.references {
			cti.References = append(cti.References, models.Reference{
				SourceName:  ref.SourceName,
				Description: ref.Description,
				URL:         ref.URL,
			})
		}

		for _, rel := range relationships[id] {
			for _, ref := range rel.references {
				cti.References = append(cti.References, models.Reference{
					SourceName:  ref.SourceName,
					Description: ref.Description,
					URL:         ref.URL,
				})
			}

			info, ok := additionalInfos[rel.sourceRef]
			if !ok {
				return nil, xerrors.Errorf("Failed to get additionalInfo. relationship id: %s, err: broken relationships. does not exists source ref: %s", rel.id, rel.sourceRef)
			}
			if info.deprecated {
				continue
			}
			switch info.objType {
			case "attack-pattern":
				cti.MitreAttack.SubTechniques = append(cti.MitreAttack.SubTechniques, models.SubTechnique{
					Name: info.name,
				})
			case "course-of-action":
				cti.Mitigations = append(cti.Mitigations, models.Mitigation{
					Name:        info.name,
					Description: info.description,
				})
			case "intrusion-set", "malware", "tool":
				cti.MitreAttack.Procedures = append(cti.MitreAttack.Procedures, models.Procedure{
					Name:        info.name,
					Description: info.description,
				})
			case "x-mitre-data-component":
				cti.MitreAttack.DataSources = append(cti.MitreAttack.DataSources, models.DataSource{
					Name:        info.name,
					Description: info.description,
				})
			}
		}

		phases := []string{}
		for _, phase := range attackPattern.killChainPhases {
			info, ok := additionalInfos[phase]
			if !ok {
				return nil, xerrors.Errorf("Failed to get kill chain phase name. phase_name(x_mitre_shortname): %s, err: broken relationships", phase)
			}
			phases = append(phases, info.name)
		}
		cti.MitreAttack.KillChainPhases = strings.Join(phases, ", ")

		ctis = append(ctis, cti)
	}

	return ctis, nil
}

func parseAttackPattern(obj ctiObject) attackPattern {
	slices.Sort(obj.XMitrePermissionsRequired)
	slices.Sort(obj.XMitreEffectivePermissions)
	slices.Sort(obj.XMitrePlatforms)
	slices.Sort(obj.XMitreImpactType)
	slices.Sort(obj.XMitreDefenseBypassed)

	r := attackPattern{
		description:          obj.Description,
		permissionRequired:   strings.Join(obj.XMitrePermissionsRequired, ", "),
		effectivePermissions: strings.Join(obj.XMitreEffectivePermissions, ", "),
		platforms:            strings.Join(obj.XMitrePlatforms, ", "),
		impactType:           strings.Join(obj.XMitreImpactType, ", "),
		networkRequirements:  obj.XMitreNetworkRequirements,
		remoteSupport:        obj.XMitreRemoteSupport,
		defenseByPassed:      strings.Join(obj.XMitreDefenseBypassed, ", "),
		detection:            obj.XMitreDetection,
		created:              obj.Created,
		modified:             obj.Modified,
		deprecated:           obj.Revoked || obj.XMitreDeprecated,
	}

	name := obj.Name
	for _, ref := range obj.ExternalReferences {
		switch ref.SourceName {
		case "mitre-attack":
			r.id = ref.ExternalID
			name = fmt.Sprintf("%s: %s", ref.ExternalID, obj.Name)
		case "capec":
			r.capecIDs = append(r.capecIDs, ref.ExternalID)
		default:
			r.references = append(r.references, ref)
		}
	}
	r.name = name

	for _, phase := range obj.KillChainPhases {
		r.killChainPhases = append(r.killChainPhases, phase.PhaseName)
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
