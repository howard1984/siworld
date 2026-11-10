//! Complete-header work validation and local source-diversity admission.

use super::header::{Header, HeaderError};
use crate::wire::Hash;
use siworld_core::pow::{self, Work};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;

pub const TAIL_BLOCKS: u64 = 312;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRules {
    pub network: Hash,
    pub genesis: Hash,
    pub genesis_timestamp: u64,
    pub genesis_target: Hash,
    pub target_interval: u64,
    pub pow_iterations: u64,
    pub max_headers: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionError {
    Header(HeaderError),
    Rules,
    Limit,
    Link,
    Time,
    Difficulty,
    Work,
    WorkOverflow,
    Sources,
    Equivocation,
    EqualWork,
    WorkFloor,
    Empty,
}

#[derive(Clone, Debug)]
pub struct VerifiedHeaders {
    rules: HeaderRules,
    headers: Vec<Header>,
    work: Vec<Work>,
}

#[derive(Clone, Copy, Debug)]
pub struct SourceObservation<'a> {
    /// Supplied by the authenticated transport, never by peer metadata.
    pub authenticated_identity: Hash,
    pub transport_address: IpAddr,
    pub chain: &'a VerifiedHeaders,
}

impl VerifiedHeaders {
    pub fn rules(&self) -> &HeaderRules {
        &self.rules
    }
    pub fn work_at(&self, height: u64) -> Result<Work, SelectionError> {
        if height == 0 {
            return Ok(Work::zero());
        }
        usize::try_from(height - 1)
            .ok()
            .and_then(|index| self.work.get(index))
            .copied()
            .ok_or(SelectionError::Link)
    }
    pub fn timestamp_window(&self, height: u64) -> Result<VecDeque<u64>, SelectionError> {
        if height > self.height() {
            return Err(SelectionError::Link);
        }
        let first = height.saturating_sub(siworld_core::params::MEDIAN_TIME_PAST_WINDOW as u64 - 1);
        (first..=height)
            .map(|height| {
                if height == 0 {
                    Ok(self.rules.genesis_timestamp)
                } else {
                    self.header(height)
                        .map(|h| h.timestamp)
                        .ok_or(SelectionError::Link)
                }
            })
            .collect()
    }
    pub fn verify(rules: HeaderRules, headers: Vec<Header>) -> Result<Self, SelectionError> {
        if rules.network == [0; 32]
            || rules.genesis == [0; 32]
            || rules.genesis_timestamp == 0
            || rules.genesis_target == [0; 32]
            || rules.target_interval != 300
            || rules.pow_iterations > crate::state::MAX_POW_ITERATIONS
            || rules.max_headers == 0
        {
            return Err(SelectionError::Rules);
        }
        if headers.len() > rules.max_headers {
            return Err(SelectionError::Limit);
        }
        let mut parent = rules.genesis;
        let mut timestamps = VecDeque::from([rules.genesis_timestamp]);
        let mut work = Vec::new();
        work.try_reserve_exact(headers.len())
            .map_err(|_| SelectionError::Limit)?;
        let mut cumulative = Work::zero();
        for (index, header) in headers.iter().enumerate() {
            if header.network != rules.network
                || header.height != index as u64 + 1
                || header.parent != parent
            {
                return Err(SelectionError::Link);
            }
            let times: Vec<_> = timestamps.iter().copied().collect();
            if header.timestamp <= pow::median_time_past(&times).ok_or(SelectionError::Time)? {
                return Err(SelectionError::Time);
            }
            let target = pow::asert_target(
                &rules.genesis_target,
                rules.genesis_timestamp,
                rules.target_interval,
                index as u64,
                *timestamps.back().ok_or(SelectionError::Time)?,
            );
            if header.target != target {
                return Err(SelectionError::Difficulty);
            }
            let seed = header.pow_seed().map_err(SelectionError::Header)?;
            if !pow::meets_target(
                &pow::pow_hash(&seed, header.nonce, rules.pow_iterations),
                &header.target,
            ) {
                return Err(SelectionError::Work);
            }
            cumulative = cumulative
                .checked_add(pow::block_work(&header.target))
                .ok_or(SelectionError::WorkOverflow)?;
            work.push(cumulative);
            parent = header.id().map_err(SelectionError::Header)?;
            timestamps.push_back(header.timestamp);
            while timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
                timestamps.pop_front();
            }
        }
        Ok(Self {
            rules,
            headers,
            work,
        })
    }
    pub fn height(&self) -> u64 {
        self.headers.len() as u64
    }
    pub fn cumulative_work(&self) -> Work {
        self.work.last().copied().unwrap_or_default()
    }
    pub fn id(&self, height: u64) -> Result<Hash, SelectionError> {
        if height == 0 {
            return Ok(self.rules.genesis);
        }
        self.header(height)
            .ok_or(SelectionError::Link)?
            .id()
            .map_err(SelectionError::Header)
    }
    pub fn header(&self, height: u64) -> Option<&Header> {
        usize::try_from(height.checked_sub(1)?)
            .ok()
            .and_then(|index| self.headers.get(index))
    }
    pub fn anchor_height(&self) -> u64 {
        self.height().saturating_sub(TAIL_BLOCKS)
    }
    pub fn tail_work(&self) -> Work {
        let anchor = self.anchor_height();
        let base = if anchor == 0 {
            Work::zero()
        } else {
            self.work[anchor as usize - 1]
        };
        self.cumulative_work() - base
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SourceGroup {
    V4([u8; 2]),
    V6([u8; 4]),
}

fn source_group(ip: IpAddr) -> SourceGroup {
    match ip {
        IpAddr::V4(ip) => SourceGroup::V4(ip.octets()[..2].try_into().expect("IPv4 prefix")),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => source_group(IpAddr::V4(v4)),
            None => SourceGroup::V6(ip.octets()[..4].try_into().expect("IPv6 prefix")),
        },
    }
}

pub fn select<'a>(
    observations: &[SourceObservation<'a>],
    floor: Work,
) -> Result<&'a VerifiedHeaders, SelectionError> {
    if floor.is_zero() {
        return Err(SelectionError::WorkFloor);
    }
    if observations.len() < 3 || observations.len() > 64 {
        return Err(SelectionError::Sources);
    }
    let first = observations.first().ok_or(SelectionError::Sources)?.chain;
    let mut identities = BTreeMap::new();
    let mut groups = BTreeSet::new();
    let mut selected = first;
    let mut equal_competitor = false;
    for source in observations {
        if source.authenticated_identity == [0; 32] || source.chain.rules != first.rules {
            return Err(SelectionError::Sources);
        }
        let group = source_group(source.transport_address);
        let tip = source.chain.id(source.chain.height())?;
        if let Some((prior_tip, _prior_group)) = identities.get(&source.authenticated_identity) {
            if prior_tip != &tip {
                return Err(SelectionError::Equivocation);
            }
        } else {
            identities.insert(source.authenticated_identity, (tip, group.clone()));
            groups.insert(group);
        }
        if source.chain.cumulative_work() > selected.cumulative_work() {
            selected = source.chain;
            equal_competitor = false;
        } else if source.chain.cumulative_work() == selected.cumulative_work()
            && tip != selected.id(selected.height())?
        {
            equal_competitor = true;
        }
    }
    if identities.len() < 3 || groups.len() < 3 {
        return Err(SelectionError::Sources);
    }
    if equal_competitor {
        return Err(SelectionError::EqualWork);
    }
    if selected.tail_work() < floor {
        return Err(SelectionError::WorkFloor);
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_core::pow;

    fn rules() -> HeaderRules {
        HeaderRules {
            network: [1; 32],
            genesis: [2; 32],
            genesis_timestamp: 1,
            genesis_target: [0xff; 32],
            target_interval: 300,
            pow_iterations: 0,
            max_headers: 1000,
        }
    }
    fn headers(count: u64, tag: u8) -> Vec<Header> {
        let rules = rules();
        let mut parent = rules.genesis;
        let mut result = Vec::new();
        for height in 1..=count {
            let header = Header {
                network: rules.network,
                height,
                parent,
                timestamp: rules.genesis_timestamp + height * 300,
                target: [0xff; 32],
                execution_commitment: [tag; 32],
                body_commitment: [7; 32],
                nonce: 0,
            };
            assert!(pow::meets_target(
                &pow::pow_hash(&header.pow_seed().unwrap(), 0, 0),
                &header.target
            ));
            parent = header.id().unwrap();
            result.push(header);
        }
        result
    }
    fn chain(count: u64, tag: u8) -> VerifiedHeaders {
        VerifiedHeaders::verify(rules(), headers(count, tag)).unwrap()
    }
    fn sources(chain: &VerifiedHeaders) -> Vec<SourceObservation<'_>> {
        (1..=3)
            .map(|i| SourceObservation {
                authenticated_identity: [i; 32],
                transport_address: IpAddr::from([10, i, 0, 1]),
                chain,
            })
            .collect()
    }

    #[test]
    fn validates_all_headers_and_locally_derives_work() {
        let c = chain(313, 3);
        assert_eq!(c.height(), 313);
        assert_eq!(c.cumulative_work(), Work::from(313));
        assert_eq!(c.anchor_height(), 1);
        assert_eq!(c.tail_work(), Work::from(312));
        assert_eq!(c.id(0), Ok(rules().genesis));
        assert_eq!(c.header(1).unwrap().height, 1);
        assert!(c.id(314).is_err());
    }

    #[test]
    fn rejects_substituted_link_network_time_and_difficulty() {
        for changed in 0..5 {
            let mut h = headers(3, 3);
            match changed {
                0 => h[1].network = [9; 32],
                1 => h[1].parent = [9; 32],
                2 => h[1].height = 7,
                3 => h[1].timestamp = 1,
                _ => h[1].target[0] = 0,
            }
            assert!(VerifiedHeaders::verify(rules(), h).is_err());
        }
        let mut limited = rules();
        limited.max_headers = 2;
        assert_eq!(
            VerifiedHeaders::verify(limited, headers(3, 3)).unwrap_err(),
            SelectionError::Limit
        );
        let mut invalid = rules();
        invalid.genesis_target = [0; 32];
        assert_eq!(
            VerifiedHeaders::verify(invalid, headers(3, 3)).unwrap_err(),
            SelectionError::Rules
        );
    }

    #[test]
    fn false_header_work_is_rejected_without_nonce_search() {
        let mut r = rules();
        r.genesis_target = [0; 32];
        r.genesis_target[31] = 1;
        let mut h = headers(1, 3);
        h[0].target = r.genesis_target;
        assert_eq!(
            VerifiedHeaders::verify(r, h).unwrap_err(),
            SelectionError::Work
        );
    }

    #[test]
    fn three_authenticated_identities_and_transport_groups_are_required() {
        let c = chain(2, 3);
        let mut s = sources(&c);
        assert!(select(&s, Work::one()).is_ok());
        assert_eq!(
            select(&s[..2], Work::one()).unwrap_err(),
            SelectionError::Sources
        );
        s[2].transport_address = IpAddr::from([10, 2, 8, 8]);
        assert_eq!(
            select(&s, Work::one()).unwrap_err(),
            SelectionError::Sources
        );
        s = sources(&c);
        s[2].authenticated_identity = s[1].authenticated_identity;
        assert_eq!(
            select(&s, Work::one()).unwrap_err(),
            SelectionError::Sources
        );
        s = sources(&c);
        s[2].transport_address = "::ffff:10.2.8.8".parse().unwrap();
        assert_eq!(
            select(&s, Work::one()).unwrap_err(),
            SelectionError::Sources
        );
    }

    #[test]
    fn selects_unique_greatest_work_without_majority_or_timing() {
        let short = chain(1, 3);
        let longest = chain(3, 5);
        let mut s = sources(&short);
        s[2].chain = &longest;
        assert_eq!(select(&s, Work::one()).unwrap().id(3), longest.id(3));
        let competing = chain(3, 6);
        s[1].chain = &competing;
        assert_eq!(
            select(&s, Work::one()).unwrap_err(),
            SelectionError::EqualWork
        );
        s[1].authenticated_identity = s[2].authenticated_identity;
        assert_eq!(
            select(&s, Work::one()).unwrap_err(),
            SelectionError::Equivocation
        );
    }

    #[test]
    fn short_history_uses_genesis_and_work_floor_never_relaxes() {
        for count in [0, 1, 312, 313] {
            let c = chain(count, 3);
            assert_eq!(c.anchor_height(), count.saturating_sub(312));
            assert_eq!(c.tail_work(), Work::from(count.min(312)));
        }
        let c = chain(3, 3);
        let s = sources(&c);
        assert_eq!(
            select(&s, Work::zero()).unwrap_err(),
            SelectionError::WorkFloor
        );
        assert_eq!(
            select(&s, Work::from(4)).unwrap_err(),
            SelectionError::WorkFloor
        );
        assert!(select(&s, Work::from(3)).is_ok());
    }
}
