package dto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCustomMenuItemsPreservesEnglishLabel(t *testing.T) {
	items := ParseCustomMenuItems(`[{"id":"redeem-center","label":"兑换中心","label_en":"Redemption Center","visibility":"user","sort_order":0}]`)

	require.Len(t, items, 1)
	require.Equal(t, "兑换中心", items[0].Label)
	require.Equal(t, "Redemption Center", items[0].LabelEN)
}
