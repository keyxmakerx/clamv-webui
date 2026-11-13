//! Authentication and authorisation primitives.

pub mod bootstrap;
pub mod lockout;
pub mod login;
pub mod oidc;
pub mod password;
pub mod ratelimit;
pub mod token;

use std::fmt;
use std::str::FromStr;

/// Cumulative roles: each one includes everything below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "VIEWER",
            Role::Operator => "OPERATOR",
            Role::Admin => "ADMIN",
        }
    }

    pub fn allows(self, needed: Role) -> bool {
        self >= needed
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_uppercase().as_str() {
            "VIEWER" => Ok(Role::Viewer),
            "OPERATOR" => Ok(Role::Operator),
            "ADMIN" => Ok(Role::Admin),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_cumulative() {
        assert!(Role::Admin.allows(Role::Operator));
        assert!(Role::Operator.allows(Role::Viewer));
        assert!(!Role::Viewer.allows(Role::Operator));
        assert_eq!("operator".parse::<Role>(), Ok(Role::Operator));
        assert!("root".parse::<Role>().is_err());
    }
}
