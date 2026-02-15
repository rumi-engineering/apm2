//! Maps FAC lane configuration to systemd unit configuration.
//!
//! This module is the authoritative conversion point for lane + constraint
//! inputs into systemd-style execution guardrails (resource limits + timeouts +
//! kill mode).

use super::job_spec::JobConstraints;
use crate::fac::lane::LaneProfileV1;

/// Systemd unit properties derived from FAC lane profile + job constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitProperties {
    /// CPU quota as a percent (`200` == 2 cores).
    pub cpu_quota_percent: u32,
    /// Memory ceiling in bytes (`MemoryMax`).
    pub memory_max_bytes: u64,
    /// Maximum number of tasks/processes (`TasksMax`).
    pub tasks_max: u32,
    /// I/O weight (`IOWeight`).
    pub io_weight: u32,
    /// Job start timeout in seconds (`TimeoutStartSec`).
    pub timeout_start_sec: u64,
    /// Job runtime timeout in seconds (`RuntimeMaxSec`).
    pub runtime_max_sec: u64,
    /// How systemd stops children (`KillMode`).
    pub kill_mode: String,
}

impl SystemdUnitProperties {
    /// Build properties from lane profile and job constraints.
    ///
    /// Job constraints override lane defaults using MIN semantics:
    /// - `memory_max_bytes` = min(`profile.memory_max_bytes`,
    ///   `constraints.memory_max_bytes`)
    /// - `timeout_start_sec` = min(`profile.test_timeout_seconds`,
    ///   `constraints.test_timeout_seconds`)
    #[must_use]
    pub fn from_lane_profile(
        profile: &LaneProfileV1,
        job_constraints: Option<&JobConstraints>,
    ) -> Self {
        let resource_profile = &profile.resource_profile;
        let timeouts = &profile.timeouts;

        let memory_max_bytes = job_constraints
            .and_then(|constraints| constraints.memory_max_bytes)
            .map_or(resource_profile.memory_max_bytes, |value| {
                value.min(resource_profile.memory_max_bytes)
            });

        let timeout_start_sec = job_constraints
            .and_then(|constraints| constraints.test_timeout_seconds)
            .map_or(timeouts.test_timeout_seconds, |value| {
                value.min(timeouts.test_timeout_seconds)
            });

        Self {
            cpu_quota_percent: resource_profile.cpu_quota_percent,
            memory_max_bytes,
            tasks_max: resource_profile.pids_max,
            io_weight: resource_profile.io_weight,
            timeout_start_sec,
            runtime_max_sec: timeouts.job_runtime_max_seconds,
            kill_mode: "control-group".to_string(),
        }
    }

    /// Render properties as `[Service]` directives.
    #[must_use]
    pub fn to_unit_directives(&self) -> String {
        [
            format!("CPUQuota={}%", self.cpu_quota_percent),
            format!("MemoryMax={}", self.memory_max_bytes),
            format!("TasksMax={}", self.tasks_max),
            format!("IOWeight={}", self.io_weight),
            format!("TimeoutStartSec={}", self.timeout_start_sec),
            format!("RuntimeMaxSec={}", self.runtime_max_sec),
            format!("KillMode={}", self.kill_mode),
        ]
        .join("\n")
    }

    /// Render properties as D-Bus transient unit properties.
    #[must_use]
    pub fn to_dbus_properties(&self) -> Vec<(String, String)> {
        vec![
            (
                "CPUQuota".to_string(),
                format!("{}%", self.cpu_quota_percent),
            ),
            ("MemoryMax".to_string(), self.memory_max_bytes.to_string()),
            ("TasksMax".to_string(), self.tasks_max.to_string()),
            ("IOWeight".to_string(), self.io_weight.to_string()),
            (
                "TimeoutStartSec".to_string(),
                self.timeout_start_sec.to_string(),
            ),
            (
                "RuntimeMaxSec".to_string(),
                self.runtime_max_sec.to_string(),
            ),
            ("KillMode".to_string(), self.kill_mode.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::lane::{LanePolicy, LaneTimeouts, ResourceProfile};

    #[test]
    fn from_lane_profile_uses_lane_defaults_without_overrides() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile(&profile, None);

        assert_eq!(properties.cpu_quota_percent, 200);
        assert_eq!(properties.memory_max_bytes, 51_539_607_552);
        assert_eq!(properties.tasks_max, 1536);
        assert_eq!(properties.io_weight, 100);
        assert_eq!(properties.timeout_start_sec, 600);
        assert_eq!(properties.runtime_max_sec, 1800);
        assert_eq!(properties.kill_mode, "control-group");
    }

    #[test]
    fn from_lane_profile_enforces_min_constraints_semantics() {
        let mut profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        profile.resource_profile.memory_max_bytes = 10_000;
        profile.timeouts.test_timeout_seconds = 600;

        let constraints = JobConstraints {
            require_nextest: false,
            memory_max_bytes: Some(1_000),
            test_timeout_seconds: Some(120),
        };
        let properties = SystemdUnitProperties::from_lane_profile(&profile, Some(&constraints));

        assert_eq!(properties.memory_max_bytes, 1_000);
        assert_eq!(properties.timeout_start_sec, 120);

        let loose_constraints = JobConstraints {
            require_nextest: false,
            memory_max_bytes: Some(20_000),
            test_timeout_seconds: Some(600),
        };
        let constrained_properties =
            SystemdUnitProperties::from_lane_profile(&profile, Some(&loose_constraints));

        assert_eq!(constrained_properties.memory_max_bytes, 10_000);
        assert_eq!(constrained_properties.timeout_start_sec, 600);
    }

    #[test]
    fn to_unit_directives_matches_expected_format() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile(&profile, None);

        let directives = properties.to_unit_directives();
        let expected = [
            "CPUQuota=200%",
            "MemoryMax=51539607552",
            "TasksMax=1536",
            "IOWeight=100",
            "TimeoutStartSec=600",
            "RuntimeMaxSec=1800",
            "KillMode=control-group",
        ];

        assert_eq!(directives, expected.join("\n"));
    }

    #[test]
    fn to_dbus_properties_matches_expected_format() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile(&profile, None);

        let properties = properties.to_dbus_properties();
        let expected = vec![
            ("CPUQuota".to_string(), "200%".to_string()),
            ("MemoryMax".to_string(), "51539607552".to_string()),
            ("TasksMax".to_string(), "1536".to_string()),
            ("IOWeight".to_string(), "100".to_string()),
            ("TimeoutStartSec".to_string(), "600".to_string()),
            ("RuntimeMaxSec".to_string(), "1800".to_string()),
            ("KillMode".to_string(), "control-group".to_string()),
        ];

        assert_eq!(properties, expected);
    }

    #[test]
    fn handles_zero_and_max_edge_values() {
        let zero_profile = LaneProfileV1 {
            schema: "apm2.fac.lane_profile.v1".to_string(),
            lane_id: "lane-00".to_string(),
            node_fingerprint: "b3-256:node".to_string(),
            boundary_id: "boundary-00".to_string(),
            resource_profile: ResourceProfile {
                cpu_quota_percent: 0,
                memory_max_bytes: 0,
                pids_max: 0,
                io_weight: 0,
            },
            timeouts: LaneTimeouts {
                test_timeout_seconds: 0,
                job_runtime_max_seconds: 0,
            },
            policy: LanePolicy::default(),
        };

        let zero_properties = SystemdUnitProperties::from_lane_profile(
            &zero_profile,
            Some(&JobConstraints {
                require_nextest: false,
                test_timeout_seconds: Some(0),
                memory_max_bytes: Some(0),
            }),
        );

        assert_eq!(zero_properties.cpu_quota_percent, 0);
        assert_eq!(zero_properties.memory_max_bytes, 0);
        assert_eq!(zero_properties.tasks_max, 0);
        assert_eq!(zero_properties.io_weight, 0);
        assert_eq!(zero_properties.timeout_start_sec, 0);
        assert_eq!(zero_properties.runtime_max_sec, 0);

        let max_profile = LaneProfileV1 {
            schema: "apm2.fac.lane_profile.v1".to_string(),
            lane_id: "lane-00".to_string(),
            node_fingerprint: "b3-256:node".to_string(),
            boundary_id: "boundary-00".to_string(),
            resource_profile: ResourceProfile {
                cpu_quota_percent: u32::MAX,
                memory_max_bytes: u64::MAX,
                pids_max: u32::MAX,
                io_weight: u32::MAX,
            },
            timeouts: LaneTimeouts {
                test_timeout_seconds: u64::MAX,
                job_runtime_max_seconds: u64::MAX,
            },
            policy: LanePolicy::default(),
        };

        let max_properties = SystemdUnitProperties::from_lane_profile(
            &max_profile,
            Some(&JobConstraints {
                require_nextest: false,
                test_timeout_seconds: Some(u64::MAX),
                memory_max_bytes: Some(u64::MAX),
            }),
        );

        assert_eq!(max_properties.cpu_quota_percent, u32::MAX);
        assert_eq!(max_properties.memory_max_bytes, u64::MAX);
        assert_eq!(max_properties.tasks_max, u32::MAX);
        assert_eq!(max_properties.io_weight, u32::MAX);
        assert_eq!(max_properties.timeout_start_sec, u64::MAX);
        assert_eq!(max_properties.runtime_max_sec, u64::MAX);
    }
}
