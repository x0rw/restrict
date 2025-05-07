use restrict::*;
#[cfg(test)]
mod tests {
    use super::*;
    use restrict::policy::Policy;
    use syscall::Syscall;

    #[test]
    fn test_create_policy_with_default_action_allow() {
        let policy = Policy::allow_all();
        assert!(policy.is_ok(), "Allow all policy creation failed");
    }

    #[test]
    fn test_create_policy_with_default_action_deny() {
        let policy = Policy::deny_all();
        assert!(policy.is_ok(), "Deny all policy creation failed");
    }

    #[test]
    fn test_redundunt_allow_policy() {
        let mut policy = Policy::allow_all().unwrap();
        let result = policy.allow(Syscall::Read);

        match result {
            Err(SeccompError::RedundantAllowRule(Syscall::Read)) => {}
            _ => panic!("Expected RedundantAllowRule for Syscall::Read"),
        }
    }

    #[test]
    fn test_redundunt_deny_policy() {
        let mut policy = Policy::deny_all().unwrap();
        let result = policy.deny(Syscall::Read);

        match result {
            Err(SeccompError::RedundantDenyRule(Syscall::Read)) => {}
            _ => panic!("Expected RedundantDenyRule for Syscall::Read"),
        }
    }
    #[test]
    fn test_policy_rules() {
        let mut policy = Policy::deny_all().unwrap();
        let result = policy
            .allow(Syscall::Read)
            .unwrap()
            .allow(Syscall::Mknod)
            .unwrap()
            .allow(Syscall::Iopl)
            .unwrap();

        assert_eq!(
            result.rules_len(),
            3,
            "Policy should not have conflicting default rules"
        );
    }

    #[test]
    fn test_policy_rules_deny() {
        let mut policy = Policy::allow_all().unwrap();
        let result = policy
            .deny(Syscall::Read)
            .unwrap()
            .deny(Syscall::Mknod)
            .unwrap()
            .deny(Syscall::Iopl)
            .unwrap();

        assert_eq!(
            result.rules_len(),
            3,
            "Policy should not have conflicting default rules"
        );
    }
}
