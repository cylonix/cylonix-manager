package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
)

type FwStat struct {
	Model
	ParentID       ID     `gorm:"type:uuid"`
	ParentType     string
	LastSeen       uint64
	AllowedRx      uint64
	AllowedRxBytes uint64
	AllowedTx      uint64
	AllowedTxBytes uint64
	DeniedRx       uint64
	DeniedRxBytes  uint64
	DeniedTx       uint64
	DeniedTxBytes  uint64
	DroppedRx      uint64
	DroppedRxBytes uint64
	DroppedTx      uint64
	DroppedTxBytes uint64
}

func (s *FwStat) ToModel() *models.FirewallStats {
	if s == nil {
		return nil
	}
	return &models.FirewallStats{
		AllowedRx:      optional.Uint64P(s.AllowedRx),
		AllowedRxBytes: optional.Uint64P(s.AllowedRxBytes),
		AllowedTx:      optional.Uint64P(s.AllowedTx),
		AllowedTxBytes: optional.Uint64P(s.AllowedTxBytes),
		DeniedRx:       optional.Uint64P(s.DeniedRx),
		DeniedRxBytes:  optional.Uint64P(s.DeniedRxBytes),
		DeniedTx:       optional.Uint64P(s.DeniedTxBytes),
		DroppedRx:      optional.Uint64P(s.DroppedRx),
		DroppedRxBytes: optional.Uint64P(s.DroppedRxBytes),
		DroppedTx:      optional.Uint64P(s.DroppedTx),
		DroppedTxBytes: optional.Uint64P(s.DroppedTxBytes),
	}
}
