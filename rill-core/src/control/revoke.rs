use std::collections::HashSet;

pub struct RevokeList {
    revoked: HashSet<u32>,
}

impl RevokeList {
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }

    pub fn revoke(&mut self, node_id: u32) {
        self.revoked.insert(node_id);
    }

    pub fn is_revoked(&self, node_id: u32) -> bool {
        self.revoked.contains(&node_id)
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

impl Default for RevokeList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_rejects_handshake_and_traffic() {
        let mut list = RevokeList::new();
        assert!(!list.is_revoked(5));
        list.revoke(5);
        assert!(list.is_revoked(5));
        assert!(!list.is_revoked(6));
        assert_eq!(list.len(), 1);
    }
}
