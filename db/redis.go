package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
  ┌───┬────────────────┬─────────────┬─────────────────────────┐
  │NO │      KEY       │    MEMBER   │       PURPOSE           │
  └───┴────────────────┴─────────────┴─────────────────────────┘
  ┌───┬────────────────┬─────────────┬─────────────────────────┐
  │ 1 │ CTI#CVE#$CVEID │ $CTIID │ TO GET CTIID FROM CVEID │
  └───┴────────────────┴─────────────┴─────────────────────────┘

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
func (r *RedisDriver) OpenDB(_, dbPath string, _ bool, option Option) (bool, error) {
	return false, r.connectRedis(dbPath, option)
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

func (r *RedisDriver) InsertCti(ctis []models.Cti, mappings []models.Mapping) error {
	ctx := context.Background()
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return xerrors.New("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"cti": {"CTI-ID": {}}, "mapping": {"CVE-ID": {"CTI-ID": {}}}}
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
	bar := pb.StartNew(len(ctis))
	for idx := range chunkSlice(len(ctis), batchSize) {
		pipe := r.conn.Pipeline()
		for _, cti := range ctis[idx.From:idx.To] {
			j, err := json.Marshal(cti)
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			_ = pipe.Set(ctx, fmt.Sprintf(ctiIDKeyFormat, cti.CtiID), j, 0)
			if _, ok := newDeps["cti"][cti.CtiID]; !ok {
				newDeps["cti"][cti.CtiID] = map[string]struct{}{}
			}
			if _, ok := oldDeps["cti"][cti.CtiID]; ok {
				delete(oldDeps["cti"], cti.CtiID)
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("Inserting CVE-ID to CTI-ID Mappings...")
	bar = pb.StartNew(len(mappings))
	for idx := range chunkSlice(len(mappings), batchSize) {
		pipe := r.conn.Pipeline()
		for _, mapping := range mappings[idx.From:idx.To] {
			for _, ctiID := range mapping.CtiIDs {
				_ = pipe.SAdd(ctx, fmt.Sprintf(cveIDKeyFormat, mapping.CveID), ctiID.CtiID)

				if _, ok := newDeps["mapping"][mapping.CveID]; !ok {
					newDeps["mapping"][mapping.CveID] = map[string]struct{}{}
				}
				newDeps["mapping"][mapping.CveID][ctiID.CtiID] = struct{}{}
				if _, ok := oldDeps["mapping"][mapping.CveID]; ok {
					delete(oldDeps["mapping"][mapping.CveID], ctiID.CtiID)
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

	pipe := r.conn.Pipeline()
	for ctiID := range oldDeps["cti"] {
		_ = pipe.Del(ctx, fmt.Sprintf(ctiIDKeyFormat, ctiID))
	}
	for cveID, ctiIDs := range oldDeps["mapping"] {
		_ = pipe.SRem(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), maps.Keys(ctiIDs))
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

// GetCtiByCveID :
func (r *RedisDriver) GetCtiByCveID(cveID string) ([]models.Cti, error) {
	ctx := context.Background()

	ctiIDs, err := r.conn.SMembers(ctx, fmt.Sprintf(cveIDKeyFormat, cveID)).Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to SMembers. key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), err)
	}

	pipe := r.conn.Pipeline()
	for _, ctiID := range ctiIDs {
		_ = pipe.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, ctiID))
	}
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, xerrors.Errorf("Failed to exec pipeline. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. ctiIDs: %q, err: %w", ctiIDs, err)
		}
		return nil, xerrors.Errorf("Failed to exec pipeline. ctiIDs: %q, err: %w", ctiIDs, err)
	}

	ctis := []models.Cti{}
	for i, cmder := range cmders {
		res, err := cmder.(*redis.StringCmd).Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to Get. CVE key: %s, CTI key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), fmt.Sprintf(ctiIDKeyFormat, ctiIDs[i]), err)
		}

		var cti models.Cti
		if err := json.Unmarshal([]byte(res), &cti); err != nil {
			return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
		}
		ctis = append(ctis, cti)
	}
	return ctis, nil
}

// GetCtiByMultiCveID :
func (r *RedisDriver) GetCtiByMultiCveID(cveIDs []string) (map[string][]models.Cti, error) {
	ctx := context.Background()

	m := map[string]*redis.StringSliceCmd{}
	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		m[cveID] = pipe.SMembers(ctx, fmt.Sprintf(cveIDKeyFormat, cveID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	ctis := map[string][]models.Cti{}
	for cveID, cmd := range m {
		ctiIDs, err := cmd.Result()
		if err != nil {
			return nil, xerrors.Errorf("Failed to SMembers. key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), err)
		}

		pipe := r.conn.Pipeline()
		for _, ctiID := range ctiIDs {
			_ = pipe.Get(ctx, fmt.Sprintf(ctiIDKeyFormat, ctiID))
		}
		cmders, err := pipe.Exec(ctx)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil, xerrors.Errorf("Failed to exec pipeline. DB relationship may be broken, use `$ go-cti fetch threat` to recreate DB. ctiIDs: %q, err: %w", ctiIDs, err)
			}
			return nil, xerrors.Errorf("Failed to exec pipeline. ctiIDs: %q, err: %w", ctiIDs, err)
		}

		var cs []models.Cti
		for i, cmder := range cmders {
			res, err := cmder.(*redis.StringCmd).Result()
			if err != nil {
				return nil, xerrors.Errorf("Failed to Get. CVE key: %s, CTI key: %s, err: %w", fmt.Sprintf(cveIDKeyFormat, cveID), fmt.Sprintf(ctiIDKeyFormat, ctiIDs[i]), err)
			}

			var cti models.Cti
			if err := json.Unmarshal([]byte(res), &cti); err != nil {
				return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			cs = append(cs, cti)
		}
		ctis[cveID] = cs
	}
	return ctis, nil
}
