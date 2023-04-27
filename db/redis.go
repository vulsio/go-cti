package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-cti/config"
	"github.com/vulsio/go-cti/models"
)

/**
# Redis Data Structure
- Strings
  ┌───┬────────────────┬────────┬──────────────────────────────────────────────────┐
  │NO │      KEY       │ MEMBER │                    PURPOSE                       │
  └───┴────────────────┴────────┴──────────────────────────────────────────────────┘
  ┌───┬────────────────┬────────┬──────────────────────────────────────────────────┐
  │ 1 │ CTI#CTI#$CTIID │  JSON  │ TO GET CTI FROM CTIID                            │
  ├───┼────────────────┼────────┼──────────────────────────────────────────────────┤
  │ 2 │ CTI#DEP        │  JSON  │ TO DELETE OUTDATED AND UNNEEDED FIELD AND MEMBER │
  └───┴────────────────┴────────┴──────────────────────────────────────────────────┘

- Sets
  ┌───┬─────────────────────┬──────────────┬─────────────────────────────────────┐
  │NO │        KEY          │    MEMBER    │             PURPOSE                 │
  └───┴─────────────────────┴──────────────┴─────────────────────────────────────┘
  ┌───┬─────────────────────┬──────────────┬─────────────────────────────────────┐
  │ 1 │ CTI#CVE#$CVEID      │ $TECHNIQUEID │ TO GET TECHNIQUEIDs FROM CVEID      │
  ├───┼─────────────────────┼──────────────┼─────────────────────────────────────┤
  │ 2 │ CTI#ATK#$ATTACKERID │ $TECHNIQUEID │ TO GET TECHNIQUEIDs FROM ATTACKERID │
  └───┴─────────────────────┴──────────────┴─────────────────────────────────────┘

  - Hash
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │NO │     KEY        │   FIELD       │     VALUE    │           PURPOSE            │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │ 1 │ CTI#FETCHMETA  │   Revision    │    string    │ GET Go-CTI Binary Revision   │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 2 │ CTI#FETCHMETA  │ SchemaVersion │     uint     │ GET Go-CTI Schema Version    │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 3 │ CTI#FETCHMETA  │ LastFetchedAt │ time.Time    │ GET Go-CTI Last Fetched Time │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
**/

const (
	dialectRedis   = "redis"
	ctiIDKeyFormat = "CTI#CTI#%s"
	cveIDKeyFormat = "CTI#CVE#%s"
	atkIDKeyFormat = "CTI#ATK#%s"
	depKey         = "CTI#DEP"
	fetchMetaKey   = "CTI#FETCHMETA"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// Name return db name
func (r *RedisDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RedisDriver) OpenDB(_, dbPath string, _ bool, option Option) error {
	if err := r.connectRedis(dbPath, option); err != nil {
		return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dialectRedis, dbPath, err)
	}
	return nil
}

func (r *RedisDriver) connectRedis(dbPath string, option Option) error {
	ctx := context.Background()
	var err error
	var opt *redis.Options
	if opt, err = redis.ParseURL(dbPath); err != nil {
		return xerrors.Errorf("Failed to parse url. err: %w", err)
	}
	if 0 < option.RedisTimeout.Seconds() {
		opt.ReadTimeout = option.RedisTimeout
	}
	r.conn = redis.NewClient(opt)
	return r.conn.Ping(ctx).Err()
}

// CloseDB close Database
func (r *RedisDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// IsGoCTIModelV1 determines if the DB was created at the time of go-cti Model v1
func (r *RedisDriver) IsGoCTIModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "CTI#*", 1).Result()
		if err != nil {
			return false, xerrors.Errorf("Failed to Scan. err: %w", err)
		}
		if len(keys) == 0 {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// GetFetchMeta get FetchMeta from Database
func (r *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GoCTIRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion, LastFetchedAt: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet Revision. err: %w", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet SchemaVersion. err: %w", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, xerrors.Errorf("Failed to ParseUint. err: %w", err)
	}

	datestr, err := r.conn.HGet(ctx, fetchMetaKey, "LastFetchedAt").Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return nil, xerrors.Errorf("Failed to HGet LastFetchedAt. err: %w", err)
		}
		datestr = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	}
	date, err := time.Parse(time.RFC3339, datestr)
	if err != nil {
		return nil, xerrors.Errorf("Failed to Parse date. err: %w", err)
	}

	return &models.FetchMeta{GoCTIRevision: revision, SchemaVersion: uint(version), LastFetchedAt: date}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": config.Revision, "SchemaVersion": models.LatestSchemaVersion, "LastFetchedAt": fetchMeta.LastFetchedAt}).Err()
}

// InsertCti :
func (r *RedisDriver) InsertCti(techniques []models.Technique, mappings []models.CveToTechniques, attackers []models.Attacker) error {
	ctx := context.Background()
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return xerrors.New("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"cti": {"CTI-ID": {}}, "mapping": {"CVE-ID or AttackID": {"TechniqueID": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{"cti": {}, "mapping": {}}
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return xerrors.Errorf("Failed to Get key: %s. err: %w", depKey, err)
		}
		oldDepsStr = `{"cti": {}, "mapping": {}}`
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return xerrors.Errorf("Failed to unmarshal JSON. err: %w", err)
	}

	log15.Info("Inserting Cyber Threat Intelligences...")

	log15.Info("Inserting Techniques...")
	bar := pb.StartNew(len(techniques))
	for idx := range chunkSlice(len(techniques), batchSize) {
		pipe := r.conn.Pipeline()
		for _, technique := range techniques[idx.From:idx.To] {
			j, err := json.Marshal(technique)
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			_ = pipe.Set(ctx, fmt.Sprintf(ctiIDKeyFormat, technique.TechniqueID), j, 0)
			newDeps["cti"][technique.TechniqueID] = map[string]struct{}{}
			delete(oldDeps["cti"], technique.TechniqueID)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting CVE-ID to CTI-ID CveToTechniques...")
	bar = pb.StartNew(len(mappings))
	for idx := range chunkSlice(len(mappings), batchSize) {
		pipe := r.conn.Pipeline()
		for _, mapping := range mappings[idx.From:idx.To] {
			cveKey := fmt.Sprintf(cveIDKeyFormat, mapping.CveID)
			if _, ok := newDeps["mapping"][mapping.CveID]; !ok {
				newDeps["mapping"][mapping.CveID] = map[string]struct{}{}
			}

			for _, ctiID := range mapping.TechniqueIDs {
				_ = pipe.SAdd(ctx, cveKey, ctiID.TechniqueID)

				newDeps["mapping"][mapping.CveID][ctiID.TechniqueID] = struct{}{}
				if _, ok := oldDeps["mapping"][mapping.CveID]; ok {
					delete(oldDeps["mapping"][mapping.CveID], ctiID.TechniqueID)
					if len(oldDeps["mapping"][mapping.CveID]) == 0 {
						delete(oldDeps["mapping"], mapping.CveID)
					}
				}
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting Attackers...")
	bar = pb.StartNew(len(attackers))
	for idx := range chunkSlice(len(attackers), batchSize) {
		pipe := r.conn.Pipeline()
		for _, attacker := range attackers[idx.From:idx.To] {
			j, err := json.Marshal(attacker)
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			_ = pipe.Set(ctx, fmt.Sprintf(ctiIDKeyFormat, attacker.AttackerID), j, 0)
			newDeps["cti"][attacker.AttackerID] = map[string]struct{}{}
			delete(oldDeps["cti"], attacker.AttackerID)

			atkKey := fmt.Sprintf(atkIDKeyFormat, attacker.AttackerID)
			if _, ok := newDeps["mapping"][attacker.AttackerID]; !ok {
				newDeps["mapping"][attacker.AttackerID] = map[string]struct{}{}
				if len(oldDeps["mapping"][attacker.AttackerID]) == 0 {
					delete(oldDeps["mapping"], attacker.AttackerID)
				}
			}

			for _, technique := range attacker.TechniquesUsed {
				_ = pipe.SAdd(ctx, atkKey, technique.TechniqueID)

				newDeps["mapping"][attacker.AttackerID][technique.TechniqueID] = struct{}{}
				if _, ok := oldDeps["mapping"][attacker.AttackerID]; ok {
					delete(oldDeps["mapping"][attacker.AttackerID], technique.TechniqueID)
					if len(oldDeps["mapping"][attacker.AttackerID]) == 0 {
						delete(oldDeps["mapping"], attacker.AttackerID)
					}
				}
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}

	pipe := r.conn.Pipeline()
	for ctiID := range oldDeps["cti"] {
		_ = pipe.Del(ctx, fmt.Sprintf(ctiIDKeyFormat, ctiID))
	}
	for id, techniqueIDs := range oldDeps["mapping"] {
		if strings.HasPrefix(id, "CVE") {
			_ = pipe.SRem(ctx, fmt.Sprintf(cveIDKeyFormat, id), maps.Keys(techniqueIDs))
		} else {
			_ = pipe.SRem(ctx, fmt.Sprintf(atkIDKeyFormat, id), maps.Keys(techniqueIDs))
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal JSON. err: %w", err)
	}
	_ = pipe.Set(ctx, depKey, string(newDepsJSON), 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	return nil
}

// GetCtiByCtiID :
func (r *RedisDriver) GetCtiByCtiID(ctiID string) (models.CTI, error) {
	ctx := context.Background()

	techniqueIDs, attackerIDs, err := classCtiIDs([]string{ctiID})
	if err != nil {
		return models.CTI{}, xerrors.Errorf("Failed to classCtiIDs. err: %w", err)
	}

	cti := models.CTI{}
	if len(techniqueIDs) > 0 {
		cti.Type = models.TechniqueType

		str, err := r.conn.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, techniqueIDs[0])).Result()
		if err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to Get. key: %s, err: %s", fmt.Sprintf(ctiIDKeyFormat, techniqueIDs[0]), err)
		}
		if err := json.Unmarshal([]byte(str), &cti.Technique); err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to Unmarshal JSON. err: %w", err)
		}
	} else {
		cti.Type = models.AttackerType

		str, err := r.conn.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, attackerIDs[0])).Result()
		if err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to Get. key: %s, err: %s", fmt.Sprintf(ctiIDKeyFormat, attackerIDs[0]), err)
		}
		if err := json.Unmarshal([]byte(str), &cti.Attacker); err != nil {
			return models.CTI{}, xerrors.Errorf("Failed to Unmarshal JSON. err: %w", err)
		}
	}

	return cti, nil
}

// GetCtisByMultiCtiID :
func (r *RedisDriver) GetCtisByMultiCtiID(ctiIDs []string) ([]models.CTI, error) {
	ctx := context.Background()

	techniqueIDs, attackerIDs, err := classCtiIDs(ctiIDs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to classCtiIDs. err: %w", err)
	}

	ctis := []models.CTI{}

	pipe := r.conn.Pipeline()
	for _, techniqueID := range techniqueIDs {
		_ = pipe.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, techniqueID))
	}
	cmders, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, xerrors.Errorf("Failed to exec pipeline. techniqueIDs: %q, err: %w", techniqueIDs, err)
	}

	for _, cmder := range cmders {
		res, err := cmder.(*redis.StringCmd).Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to Get. err: %w", err)
		}

		var technique models.Technique
		if err := json.Unmarshal([]byte(res), &technique); err != nil {
			return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
		}
		ctis = append(ctis, models.CTI{
			Type:      models.TechniqueType,
			Technique: &technique,
		})
	}

	pipe = r.conn.Pipeline()
	for _, attackerID := range attackerIDs {
		_ = pipe.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, attackerID))
	}
	cmders, err = pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, xerrors.Errorf("Failed to exec pipeline. attackerIDs: %q, err: %w", attackerIDs, err)
	}

	for _, cmder := range cmders {
		res, err := cmder.(*redis.StringCmd).Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to Get. err: %w", err)
		}

		var attacker models.Attacker
		if err := json.Unmarshal([]byte(res), &attacker); err != nil {
			return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
		}
		ctis = append(ctis, models.CTI{
			Type:     models.AttackerType,
			Attacker: &attacker,
		})
	}

	return ctis, nil
}

// GetTechniqueIDsByCveID :
func (r *RedisDriver) GetTechniqueIDsByCveID(cveID string) ([]string, error) {
	techniqueIDs, err := r.conn.SMembers(context.Background(), fmt.Sprintf(cveIDKeyFormat, cveID)).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to SMembers. key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), err)
	}
	return techniqueIDs, nil
}

// GetTechniqueIDsByMultiCveID :
func (r *RedisDriver) GetTechniqueIDsByMultiCveID(cveIDs []string) (map[string][]string, error) {
	ctx := context.Background()

	m := map[string]*redis.StringSliceCmd{}
	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		m[cveID] = pipe.SMembers(ctx, fmt.Sprintf(cveIDKeyFormat, cveID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	techniqueIDs := map[string][]string{}
	for cveID, cmd := range m {
		ids, err := cmd.Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to SMembers. key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), err)
		}
		techniqueIDs[cveID] = ids
	}
	return techniqueIDs, nil
}

// GetAttackerIDsByTechniqueIDs :
func (r *RedisDriver) GetAttackerIDsByTechniqueIDs(techniqueIDs []string) ([]string, error) {
	ctx := context.Background()

	atkKeys := []string{}

	dbsize, err := r.conn.DBSize(ctx).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to DBSize. err: %w", err)
	}

	var cursor uint64
	for {
		var keys []string
		var err error
		keys, cursor, err = r.conn.Scan(ctx, cursor, fmt.Sprintf(atkIDKeyFormat, "*"), dbsize/5).Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to Scan. err: %w", err)
		}

		atkKeys = append(atkKeys, keys...)

		if cursor == 0 {
			break
		}
	}

	m := map[string]*redis.StringSliceCmd{}
	pipe := r.conn.Pipeline()
	for _, atkKey := range atkKeys {
		m[strings.TrimPrefix(atkKey, "CTI#ATK#")] = pipe.SMembers(ctx, atkKey)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	attackerIDs := []string{}
	for atkID, cmd := range m {
		ids, err := cmd.Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to SMembers. key: %s, err: %w", fmt.Sprintf(atkIDKeyFormat, atkID), err)
		}

		attackerUsedTechniques := map[string]struct{}{}
		for _, id := range ids {
			attackerUsedTechniques[id] = struct{}{}
		}

		for _, techniqueID := range techniqueIDs {
			delete(attackerUsedTechniques, techniqueID)
			if len(attackerUsedTechniques) == 0 {
				break
			}
		}
		if len(attackerUsedTechniques) == 0 {
			attackerIDs = append(attackerIDs, atkID)
		}
	}

	return attackerIDs, nil
}
