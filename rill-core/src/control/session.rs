use super::revoke::RevokeList;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Unregistered,
    Registered { node_id: u32 },
    Reconnecting { node_id: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    RegisterOk { node_id: u32 },
    RegisterFailed,
    LinkLost,
    ChallengeOk,
    ChallengeFailed,
    Revoked { node_id: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    InvalidTransition,
}

pub struct ClientSession {
    state: SessionState,
    revoke_list: RevokeList,
}

impl ClientSession {
    pub fn new() -> Self {
        Self {
            state: SessionState::Unregistered,
            revoke_list: RevokeList::new(),
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// 重连恢复：以已知 node_id 直接进入 Reconnecting（挑战路径需要 node_id 计算 tag）
    pub fn restore(&mut self, node_id: u32) {
        self.state = SessionState::Reconnecting { node_id };
    }

    pub fn is_revoked(&self, node_id: u32) -> bool {
        self.revoke_list.is_revoked(node_id)
    }

    pub fn revoked_count(&self) -> usize {
        self.revoke_list.len()
    }

    pub fn handle(&mut self, ev: SessionEvent) -> Result<(), SessionError> {
        match (&self.state, ev) {
            (SessionState::Unregistered, SessionEvent::RegisterOk { node_id }) => {
                self.state = SessionState::Registered { node_id };
                Ok(())
            }
            (SessionState::Unregistered, SessionEvent::RegisterFailed) => Ok(()),
            (SessionState::Registered { node_id }, SessionEvent::LinkLost) => {
                self.state = SessionState::Reconnecting { node_id: *node_id };
                Ok(())
            }
            (SessionState::Reconnecting { node_id }, SessionEvent::ChallengeOk) => {
                self.state = SessionState::Registered { node_id: *node_id };
                Ok(())
            }
            (SessionState::Reconnecting { .. }, SessionEvent::ChallengeFailed) => Ok(()),
            (
                SessionState::Reconnecting { node_id },
                SessionEvent::RegisterOk { node_id: new_id },
            ) => {
                if *node_id == new_id {
                    self.state = SessionState::Registered { node_id: new_id };
                    Ok(())
                } else {
                    Err(SessionError::InvalidTransition)
                }
            }
            (
                SessionState::Registered { node_id },
                SessionEvent::RegisterOk { node_id: new_id },
            ) => {
                if *node_id == new_id {
                    Ok(())
                } else {
                    Err(SessionError::InvalidTransition)
                }
            }
            (_, SessionEvent::Revoked { node_id }) => match &self.state {
                SessionState::Registered { node_id: self_id }
                | SessionState::Reconnecting { node_id: self_id }
                    if *self_id == node_id =>
                {
                    self.revoke_list.revoke(node_id);
                    self.state = SessionState::Unregistered;
                    Ok(())
                }
                _ => {
                    self.revoke_list.revoke(node_id);
                    Ok(())
                }
            },
            (_, SessionEvent::ChallengeOk | SessionEvent::ChallengeFailed) => {
                Err(SessionError::InvalidTransition)
            }
            (_, SessionEvent::LinkLost) => Err(SessionError::InvalidTransition),
            (_, SessionEvent::RegisterFailed) => Err(SessionError::InvalidTransition),
        }
    }
}

impl Default for ClientSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(s: &mut ClientSession, id: u32) {
        s.handle(SessionEvent::RegisterOk { node_id: id }).unwrap();
    }

    #[test]
    fn happy_path_register_link_challenge() {
        let mut s = ClientSession::new();
        assert_eq!(s.state(), &SessionState::Unregistered);
        s.handle(SessionEvent::RegisterFailed).unwrap();
        assert_eq!(s.state(), &SessionState::Unregistered);
        register(&mut s, 7);
        assert_eq!(s.state(), &SessionState::Registered { node_id: 7 });
        s.handle(SessionEvent::LinkLost).unwrap();
        assert_eq!(s.state(), &SessionState::Reconnecting { node_id: 7 });
        s.handle(SessionEvent::ChallengeOk).unwrap();
        assert_eq!(s.state(), &SessionState::Registered { node_id: 7 });
    }

    #[test]
    fn challenge_failed_stays_reconnecting() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::LinkLost).unwrap();
        s.handle(SessionEvent::ChallengeFailed).unwrap();
        assert_eq!(s.state(), &SessionState::Reconnecting { node_id: 7 });
        s.handle(SessionEvent::ChallengeOk).unwrap();
        assert_eq!(s.state(), &SessionState::Registered { node_id: 7 });
    }

    #[test]
    fn reconnect_via_idempotent_register_same_id() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::LinkLost).unwrap();
        s.handle(SessionEvent::RegisterOk { node_id: 7 }).unwrap();
        assert_eq!(s.state(), &SessionState::Registered { node_id: 7 });
    }

    #[test]
    fn reconnect_register_different_id_rejected() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::LinkLost).unwrap();
        assert_eq!(
            s.handle(SessionEvent::RegisterOk { node_id: 8 }),
            Err(SessionError::InvalidTransition)
        );
        assert_eq!(s.state(), &SessionState::Reconnecting { node_id: 7 });
    }

    #[test]
    fn self_revoke_resets_to_unregistered() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::Revoked { node_id: 7 }).unwrap();
        assert_eq!(s.state(), &SessionState::Unregistered);
        assert!(s.is_revoked(7));
        s.handle(SessionEvent::LinkLost).unwrap_err();
    }

    #[test]
    fn self_revoke_during_reconnecting() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::LinkLost).unwrap();
        s.handle(SessionEvent::Revoked { node_id: 7 }).unwrap();
        assert_eq!(s.state(), &SessionState::Unregistered);
    }

    #[test]
    fn others_revoke_keeps_state() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        s.handle(SessionEvent::Revoked { node_id: 9 }).unwrap();
        assert_eq!(s.state(), &SessionState::Registered { node_id: 7 });
        assert!(s.is_revoked(9));
        assert!(!s.is_revoked(7));
    }

    #[test]
    fn revoke_while_unregistered_just_records() {
        let mut s = ClientSession::new();
        s.handle(SessionEvent::Revoked { node_id: 3 }).unwrap();
        assert_eq!(s.state(), &SessionState::Unregistered);
        assert!(s.is_revoked(3));
    }

    #[test]
    fn challenge_ok_while_registered_invalid() {
        let mut s = ClientSession::new();
        register(&mut s, 7);
        assert_eq!(
            s.handle(SessionEvent::ChallengeOk),
            Err(SessionError::InvalidTransition)
        );
    }
}
