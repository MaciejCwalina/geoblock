// Package firewall blocks remote addresses with local iptables rules.
package firewall

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
)

// Firewall blocks traffic to and from an address. Block reports whether new
// rules were added; blocking an already blocked address is a no-op.
type Firewall interface {
	Block(address netip.Addr) (added bool, err error)
	IsBlocked(address netip.Addr) bool
}

// RuleTable is the subset of *iptables.IPTables used here, so tests can run
// without root.
type RuleTable interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, position int, rulespec ...string) error
}

// IPTables drops traffic with two rules per address:
//
//	-I INPUT  -s <address> -j DROP
//	-I OUTPUT -d <address> -j DROP
//
// Rules are inserted at the top of the chain so earlier ACCEPT rules (for
// example "ESTABLISHED,RELATED") cannot bypass them.
type IPTables struct {
	rules RuleTable
	// blockMutex serialises Block so iptables is never called twice for the
	// same address; blocked has its own lock so IsBlocked never waits for an
	// iptables command to finish.
	blockMutex sync.Mutex
	blocked    addressSet
}

// NewIPTables returns a Firewall that manages rules through rules.
func NewIPTables(rules RuleTable) *IPTables {
	return &IPTables{rules: rules, blocked: newAddressSet()}
}

func ruleSpecs(address netip.Addr) [][]string {
	return [][]string{
		{"INPUT", "-s", address.String(), "-j", "DROP"},
		{"OUTPUT", "-d", address.String(), "-j", "DROP"},
	}
}

// Block implements Firewall. It checks the in-memory set first and then asks
// iptables whether each rule already exists (e.g. after a restart).
func (firewall *IPTables) Block(address netip.Addr) (bool, error) {
	firewall.blockMutex.Lock()
	defer firewall.blockMutex.Unlock()

	if firewall.blocked.contains(address) {
		return false, nil
	}

	added := false
	for _, spec := range ruleSpecs(address) {
		chain, rule := spec[0], spec[1:]
		exists, err := firewall.rules.Exists("filter", chain, rule...)
		if err != nil {
			return added, fmt.Errorf("check %s rule for %s: %w", chain, address, err)
		}
		if exists {
			continue
		}
		if err := firewall.rules.Insert("filter", chain, 1, rule...); err != nil {
			return added, fmt.Errorf("insert %s rule for %s: %w", chain, address, err)
		}
		added = true
	}
	firewall.blocked.add(address)
	return added, nil
}

// IsBlocked implements Firewall.
func (firewall *IPTables) IsBlocked(address netip.Addr) bool {
	return firewall.blocked.contains(address)
}

// DryRun only logs what it would block.
type DryRun struct {
	logger  *slog.Logger
	blocked addressSet
}

// NewDryRun returns a Firewall that never touches the system.
func NewDryRun(logger *slog.Logger) *DryRun {
	return &DryRun{logger: logger, blocked: newAddressSet()}
}

// Block implements Firewall.
func (firewall *DryRun) Block(address netip.Addr) (bool, error) {
	if !firewall.blocked.add(address) {
		return false, nil
	}
	firewall.logger.Info("dry run: would block address", "address", address)
	return true, nil
}

// IsBlocked implements Firewall.
func (firewall *DryRun) IsBlocked(address netip.Addr) bool {
	return firewall.blocked.contains(address)
}

type addressSet struct {
	mutex     *sync.RWMutex
	addresses map[netip.Addr]struct{}
}

func newAddressSet() addressSet {
	return addressSet{mutex: &sync.RWMutex{}, addresses: make(map[netip.Addr]struct{})}
}

func (set addressSet) contains(address netip.Addr) bool {
	set.mutex.RLock()
	defer set.mutex.RUnlock()
	_, found := set.addresses[address]
	return found
}

// add inserts address and reports whether it was not present before.
func (set addressSet) add(address netip.Addr) bool {
	set.mutex.Lock()
	defer set.mutex.Unlock()
	if _, found := set.addresses[address]; found {
		return false
	}
	set.addresses[address] = struct{}{}
	return true
}
