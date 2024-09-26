package capec

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/models"
	"github.com/vulsio/go-cti/utils"
)

const capecURL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

// Fetch CAPEC data
func Fetch() ([]models.Technique, error) {
	log15.Info("Fetching CAPEC...")

	res, err := utils.FetchURL(capecURL)
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch CAPEC JSON. err: %w", err)
	}
	techniques, err := parse(res)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse CAPEC Cyber Threat Intelligence. err: %w", err)
	}
	return techniques, nil
}

func parse(res []byte) ([]models.Technique, error) {
	var r root
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
	}

	attackPatterns := map[string]attackPattern{}
	additionalInfos := map[string]additionalInfoObject{}
	relationships := map[string][]relationshipObject{}
	for _, obj := range r.Objects {
		if obj.XCapecStatus == "Deprecated" {
			continue
		}

		switch obj.Type {
		case "attack-pattern":
			attackPatterns[obj.ID] = parseCAPECAttackPattern(obj)
		case "course-of-action":
			additionalInfos[obj.ID] = additionalInfoObject{
				objType:     obj.Type,
				name:        obj.Description,
				description: fmt.Sprintf("%s: %s", obj.Name, obj.Description),
			}
		case "relationship":
			relationships[obj.TargetRef] = append(relationships[obj.TargetRef], relationshipObject{
				id:               obj.ID,
				relationshipType: obj.RelationshipType,
				sourceRef:        obj.SourceRef,
				targetRef:        obj.TargetRef,
			})
		}
	}

	techniques := []models.Technique{}
	for id, attackPattern := range attackPatterns {
		technique := models.Technique{
			TechniqueID: attackPattern.id,
			Type:        models.CAPECType,
			Name:        attackPattern.name,
			Description: attackPattern.description,
			References:  []models.TechniqueReference{},
			Mitigations: []models.Mitigation{},
			Capec: &models.Capec{
				AttackIDs:           []models.AttackID{},
				Status:              attackPattern.status,
				ExtendedDescription: attackPattern.extendedDescription,
				TypicalSeverity:     attackPattern.typicalSeverity,
				LikelihoodOfAttack:  attackPattern.likelihoodOfAttack,
				Relationships:       []models.Relationship{},
				Domains:             []models.Domain{},
				AlternateTerms:      []models.AlternateTerm{},
				ExampleInstances:    []models.ExampleInstance{},
				Prerequisites:       []models.Prerequisite{},
				ResourcesRequired:   []models.ResourceRequired{},
				SkillsRequired:      []models.SkillRequired{},
				Abstraction:         attackPattern.abstraction,
				ExecutionFlow:       attackPattern.executionFlow,
				Consequences:        []models.Consequence{},
				RelatedWeaknesses:   []models.RelatedWeakness{},
			},
			Created:  attackPattern.created,
			Modified: attackPattern.modified,
		}

		for _, attackID := range attackPattern.attackIDs {
			technique.Capec.AttackIDs = append(technique.Capec.AttackIDs, models.AttackID{
				AttackID: attackID,
			})
		}

		for _, ref := range attackPattern.references {
			technique.References = append(technique.References, models.TechniqueReference{
				Reference: models.Reference{
					SourceName:  ref.SourceName,
					Description: ref.Description,
					URL:         ref.URL,
				},
			})
		}

		slices.Sort(attackPattern.domains)
		for _, domain := range slices.Compact(attackPattern.domains) {
			technique.Capec.Domains = append(technique.Capec.Domains, models.Domain{
				Domain: domain,
			})
		}

		for _, term := range attackPattern.alternateTerms {
			technique.Capec.AlternateTerms = append(technique.Capec.AlternateTerms,
				models.AlternateTerm{
					Term: term,
				})
		}

		for _, exampleInstance := range attackPattern.exampleInstances {
			technique.Capec.ExampleInstances = append(technique.Capec.ExampleInstances, models.ExampleInstance{
				Instance: exampleInstance,
			})
		}

		for _, prerequisite := range attackPattern.prerequisites {
			technique.Capec.Prerequisites = append(technique.Capec.Prerequisites, models.Prerequisite{
				Prerequisite: prerequisite,
			})
		}

		for _, resource := range attackPattern.resourcesRequired {
			technique.Capec.ResourcesRequired = append(technique.Capec.ResourcesRequired, models.ResourceRequired{
				Resource: resource,
			})
		}

		for _, nature := range []string{"ChildOf", "ParentOf", "CanFollow", "CanPrecede", "PeerOf"} {
			var refs []string
			switch nature {
			case "ChildOf":
				refs = attackPattern.childOfRefs
			case "ParentOf":
				refs = attackPattern.parentOfRefs
			case "CanFollow":
				refs = attackPattern.canFollowRefs
			case "CanPrecede":
				refs = attackPattern.canPrecedeRefs
			case "PeerOf":
				refs = attackPattern.peerOfRefs
			}

			rels, err := expandFromRefIDToName(refs, nature, attackPatterns)
			if err != nil {
				return nil, xerrors.Errorf("Failed to expand %s references. id: %s, err: %w", nature, id, err)
			}
			technique.Capec.Relationships = append(technique.Capec.Relationships, rels...)
		}

		for _, skill := range attackPattern.skillRequired {
			technique.Capec.SkillsRequired = append(technique.Capec.SkillsRequired, models.SkillRequired{
				Skill: skill,
			})
		}

		for _, consequence := range attackPattern.consequences {
			technique.Capec.Consequences = append(technique.Capec.Consequences, models.Consequence{
				Consequence: consequence,
			})
		}

		for _, cweID := range attackPattern.relatedWeaknesses {
			technique.Capec.RelatedWeaknesses = append(technique.Capec.RelatedWeaknesses, models.RelatedWeakness{
				CweID: cweID,
			})
		}

		for _, rel := range relationships[id] {
			info, ok := additionalInfos[rel.sourceRef]
			if !ok {
				return nil, xerrors.Errorf("Failed to get additionalInfo. id: %s, err: broken relationships", rel.id)
			}
			technique.Mitigations = append(technique.Mitigations, models.Mitigation{
				Name:        info.name,
				Description: info.description,
			})

		}

		techniques = append(techniques, technique)
	}

	return techniques, nil
}

func parseCAPECAttackPattern(obj ctiObject) attackPattern {
	slices.Sort(obj.XCapecDomains)

	r := attackPattern{
		status:              obj.XCapecStatus,
		abstraction:         obj.XCapecAbstraction,
		likelihoodOfAttack:  obj.XCapecLikelihoodOfAttack,
		typicalSeverity:     obj.XCapecTypicalSeverity,
		description:         obj.Description,
		extendedDescription: obj.XCapecExtendedDescription,
		alternateTerms:      obj.XCapecAlternateTerms,
		executionFlow:       obj.XCapecExecutionFlow,
		exampleInstances:    obj.XCapecExampleInstances,
		domains:             obj.XCapecDomains,
		prerequisites:       obj.XCapecPrerequisites,
		resourcesRequired:   obj.XCapecResourcesRequired,
		parentOfRefs:        obj.XCapecParentOfRefs,
		childOfRefs:         obj.XCapecChildOfRefs,
		canFollowRefs:       obj.XCapecCanFollowRefs,
		canPrecedeRefs:      obj.XCapecCanPrecedeRefs,
		peerOfRefs:          obj.XCapecPeerOfRefs,
		created:             obj.Created,
		modified:            obj.Modified,
	}

	name := obj.Name
	for _, ref := range obj.ExternalReferences {
		switch ref.SourceName {
		case "capec":
			r.id = ref.ExternalID
			name = fmt.Sprintf("%s: %s", ref.ExternalID, obj.Name)
		case "ATTACK":
			r.attackIDs = append(r.attackIDs, ref.ExternalID)
		case "cwe":
			r.relatedWeaknesses = append(r.relatedWeaknesses, ref.ExternalID)
		default:
			r.references = append(r.references, ref)
		}
	}
	r.name = name

	for scope, impacts := range obj.XCapecConsequences {
		for _, impact := range impacts {
			r.consequences = append(r.consequences, fmt.Sprintf("%s: %s", scope, impact))
		}
	}

	for level, description := range obj.XCapecSkillsRequired {
		r.skillRequired = append(r.skillRequired, fmt.Sprintf("%s: %s", level, description))
	}

	return r
}

func expandFromRefIDToName(references []string, nature string, attackPatterns map[string]attackPattern) ([]models.Relationship, error) {
	rels := []models.Relationship{}
	for _, refID := range references {
		relAttackPattern, ok := attackPatterns[refID]
		if !ok {
			return nil, xerrors.Errorf("Failed to get relational attack pattern. missing id: %s, err: broken relationships", refID)
		}
		rels = append(rels, models.Relationship{
			Nature:   nature,
			Relation: fmt.Sprintf("%s: %s", relAttackPattern.abstraction, relAttackPattern.name),
		})
	}
	return rels, nil
}
