package parser

import (
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

/* should be part of a package shared with enrich/geoip.go */
type EnrichFunc func(string, *types.Event, interface{}, *log.Entry) (map[string]string, error)
type InitFunc func(map[string]string) (interface{}, error)

type EnricherCtx struct {
	Registered map[string]*Enricher
}

type Enricher struct {
	Name         string
	InitFunc     InitFunc
	EnrichFunc   EnrichFunc
	Ctx          interface{}
	Cache        gcache.Cache
	ExcludeCache bool
}

/* mimic plugin loading */
func Loadplugin(path string) (EnricherCtx, error) {
	enricherCtx := EnricherCtx{}
	enricherCtx.Registered = make(map[string]*Enricher)

	enricherConfig := map[string]string{"datadir": path}

	EnrichersList := []*Enricher{
		{
			Name:       "GeoIpCity",
			InitFunc:   GeoIPCityInit,
			EnrichFunc: GeoIpCity,
		},
		{
			Name:       "GeoIpASN",
			InitFunc:   GeoIPASNInit,
			EnrichFunc: GeoIpASN,
		},
		{
			Name:       "IpToRange",
			InitFunc:   IpToRangeInit,
			EnrichFunc: IpToRange,
		},
		{
			Name:       "reverse_dns",
			InitFunc:   reverseDNSInit,
			EnrichFunc: reverse_dns,
		},
		{
			Name:         "ParseDate",
			InitFunc:     parseDateInit,
			EnrichFunc:   ParseDate,
			ExcludeCache: true,
		},
		{
			Name:         "UnmarshalJSON",
			InitFunc:     unmarshalInit,
			EnrichFunc:   unmarshalJSON,
			ExcludeCache: true,
		},
	}

	for _, enricher := range EnrichersList {
		log.Debugf("Initiating enricher '%s'", enricher.Name)
		pluginCtx, err := enricher.InitFunc(enricherConfig)
		if err != nil {
			log.Errorf("unable to register plugin '%s': %v", enricher.Name, err)
			continue
		}
		if fflag.EnricherCache.IsEnabled() && !enricher.ExcludeCache {
			enricher.Cache = gcache.New(50).LRU().Expiration(time.Minute).Build()
		}
		enricher.Ctx = pluginCtx
		log.Infof("Successfully registered enricher '%s'", enricher.Name)
		enricherCtx.Registered[enricher.Name] = enricher
	}

	return enricherCtx, nil
}
