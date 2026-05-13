// Package roles defines the role-based access model for the PD edition.
package roles

// Role identifies a user's access level.
type Role string

const (
	Chief         Role = "chief"
	EvidenceClerk Role = "evidence_clerk"
	TechAdmin     Role = "tech_admin"
	Officer       Role = "officer"
	Auditor       Role = "auditor"
)

// Permission constants.
const (
	PermIntake      = "intake"
	PermTransfer    = "transfer"
	PermHoldSet     = "hold:set"
	PermHoldRelease = "hold:release"
	PermExport      = "export"
	PermDestroy     = "destroy"
	PermAuditRead   = "audit:read"
	PermNodeAdmin   = "node:admin"
	PermStatus      = "status"
)

var grants = map[Role][]string{
	Chief:         {PermIntake, PermTransfer, PermHoldSet, PermHoldRelease, PermExport, PermDestroy, PermAuditRead, PermNodeAdmin, PermStatus},
	EvidenceClerk: {PermIntake, PermTransfer, PermHoldSet, PermHoldRelease, PermStatus},
	TechAdmin:     {PermNodeAdmin, PermStatus, PermAuditRead},
	Officer:       {PermIntake, PermStatus},
	Auditor:       {PermAuditRead, PermStatus},
}

// Can reports whether role has permission.
func Can(role Role, perm string) bool {
	for _, p := range grants[role] {
		if p == perm {
			return true
		}
	}
	return false
}

// Valid reports whether the role string is recognized.
func Valid(r string) bool {
	_, ok := grants[Role(r)]
	return ok
}

// All returns every defined role.
func All() []Role {
	return []Role{Chief, EvidenceClerk, TechAdmin, Officer, Auditor}
}
