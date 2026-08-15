package rbac

type Policy struct {
	allowedRoles map[string]bool
}

func NewPolicy(roles []string) Policy {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}
	return Policy{allowedRoles: allowed}
}

func (p Policy) Allows(role string) bool {
	if len(p.allowedRoles) == 0 {
		return true
	}
	return p.allowedRoles[role]
}
