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

        assert_eq!(
            result.unwrap_err(),
            SeccompError::RedundantAllowRule(Syscall::Read),
            "Policy should not have conflicting default rules"
        );
    }

    #[test]
    fn test_redundunt_deny_policy() {
        let mut policy = Policy::deny_all().unwrap();
        let result = policy.deny(Syscall::Read);

        assert_eq!(
            result.unwrap_err(),
            SeccompError::RedundantDenyRule(Syscall::Read),
            "Policy should not have conflicting default rules"
        );
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
