package firewall

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeRuleTable mimics iptables with an in-memory rule list.
type fakeRuleTable struct {
	mutex     sync.Mutex
	rules     []string
	inserts   int
	insertErr error
}

func ruleKey(table, chain string, rulespec []string) string {
	return table + " " + chain + " " + strings.Join(rulespec, " ")
}

func (table *fakeRuleTable) Exists(tableName, chain string, rulespec ...string) (bool, error) {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	return slices.Contains(table.rules, ruleKey(tableName, chain, rulespec)), nil
}

func (table *fakeRuleTable) Insert(tableName, chain string, _ int, rulespec ...string) error {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	if table.insertErr != nil {
		return table.insertErr
	}
	table.inserts++
	table.rules = append(table.rules, ruleKey(tableName, chain, rulespec))
	return nil
}

func TestIPTablesBlock(t *testing.T) {
	address := netip.MustParseAddr("1.1.1.1")
	tests := []struct {
		name          string
		existingRules []string
		blockCalls    int
		insertErr     error
		wantAdded     bool
		wantInserts   int
		wantErr       bool
		wantBlocked   bool
	}{
		{
			name:        "first block adds input and output rules",
			blockCalls:  1,
			wantAdded:   true,
			wantInserts: 2,
			wantBlocked: true,
		},
		{
			name:        "repeated blocks add rules only once",
			blockCalls:  5,
			wantAdded:   false,
			wantInserts: 2,
			wantBlocked: true,
		},
		{
			name: "rules already present after restart",
			existingRules: []string{
				"filter INPUT -s 1.1.1.1 -j DROP",
				"filter OUTPUT -d 1.1.1.1 -j DROP",
			},
			blockCalls:  1,
			wantAdded:   false,
			wantInserts: 0,
			wantBlocked: true,
		},
		{
			name:          "only the missing rule is added",
			existingRules: []string{"filter INPUT -s 1.1.1.1 -j DROP"},
			blockCalls:    1,
			wantAdded:     true,
			wantInserts:   1,
			wantBlocked:   true,
		},
		{
			name:        "insert failure is reported and not remembered",
			blockCalls:  1,
			insertErr:   errors.New("permission denied"),
			wantErr:     true,
			wantBlocked: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules := &fakeRuleTable{rules: test.existingRules, insertErr: test.insertErr}
			blocker := NewIPTables(rules)

			var (
				added bool
				err   error
			)
			for range test.blockCalls {
				added, err = blocker.Block(address)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, test.wantErr)
			}
			if test.blockCalls == 1 && added != test.wantAdded {
				t.Errorf("added = %v, want %v", added, test.wantAdded)
			}
			if rules.inserts != test.wantInserts {
				t.Errorf("inserts = %d, want %d", rules.inserts, test.wantInserts)
			}
			if blocker.IsBlocked(address) != test.wantBlocked {
				t.Errorf("IsBlocked = %v, want %v", blocker.IsBlocked(address), test.wantBlocked)
			}
		})
	}
}

func TestIPTablesBlockConcurrent(t *testing.T) {
	rules := &fakeRuleTable{}
	blocker := NewIPTables(rules)
	address := netip.MustParseAddr("1.1.1.1")

	var group sync.WaitGroup
	for range 50 {
		group.Go(func() {
			if _, err := blocker.Block(address); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if rules.inserts != 2 {
		t.Errorf("inserts = %d, want 2", rules.inserts)
	}
}

func TestDryRun(t *testing.T) {
	blocker := NewDryRun(slog.New(slog.NewTextHandler(io.Discard, nil)))
	address := netip.MustParseAddr("1.1.1.1")
	if added, _ := blocker.Block(address); !added {
		t.Error("first Block should report added")
	}
	if added, _ := blocker.Block(address); added {
		t.Error("second Block should not report added")
	}
	if !blocker.IsBlocked(address) {
		t.Error("address should be marked blocked")
	}
}
