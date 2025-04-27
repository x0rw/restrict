use restrict::*;
#[cfg(test)]
mod tests {
    use super::*;
    use restrict::policy::SeccompPolicy;
    use syscalls;
    #[test]
    fn test_allow() {
        let filter = SeccompPolicy::allow_all();
    }
}
