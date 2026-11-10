//! Unix host projections into the portable checkpoint packet format.
use super::*;

impl Tick {
    /// At most three public packets, for an existing authenticated eng2 queue.
    /// Nothing here opens a connection or sends a packet.
    pub fn messages(&self) -> Vec<Incoming> {
        let mut result = Vec::new();
        if let Some(proposal) = &self.proposal {
            result.push(Incoming::Proposal(proposal.clone()));
            if let Some(vote) = &self.vote {
                result.push(Incoming::Vote {
                    statement: proposal.statement.clone(),
                    vote: Box::new(vote.clone()),
                });
            }
        }
        if let Some(certificate) = &self.certificate {
            result.push(Incoming::Certified {
                certificate: Box::new(certificate.certificate.clone()),
                witness: certificate.witness.clone(),
            });
        }
        result
    }
}
