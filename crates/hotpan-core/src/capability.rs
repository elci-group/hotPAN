//! Discrete capabilities a device can contribute. These are what conventional
//! cloud infrastructure fundamentally cannot provide: physical sensors,
//! cellular identity, hardware keys, locally authenticated sessions and data
//! that must never leave the device.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Capability {
    Camera,
    Microphone,
    Gps,
    Cellular,
    Bluetooth,
    Nfc,
    Accelerometer,
    Gpu,
    HardwareKeystore,
    LanPresence,
    /// Data tagged `tag` lives on this device (and may be required to stay there).
    LocalData(String),
    /// A locally authenticated session for service `name` exists on this device.
    Session(String),
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Camera => f.write_str("camera"),
            Capability::Microphone => f.write_str("microphone"),
            Capability::Gps => f.write_str("gps"),
            Capability::Cellular => f.write_str("cellular"),
            Capability::Bluetooth => f.write_str("bluetooth"),
            Capability::Nfc => f.write_str("nfc"),
            Capability::Accelerometer => f.write_str("accelerometer"),
            Capability::Gpu => f.write_str("gpu"),
            Capability::HardwareKeystore => f.write_str("hardware_keystore"),
            Capability::LanPresence => f.write_str("lan_presence"),
            Capability::LocalData(t) => write!(f, "local_data:{t}"),
            Capability::Session(s) => write!(f, "session:{s}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown capability `{0}`")]
pub struct UnknownCapability(pub String);

impl FromStr for Capability {
    type Err = UnknownCapability;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(tag) = s.strip_prefix("local_data:") {
            if !tag.is_empty() {
                return Ok(Capability::LocalData(tag.to_string()));
            }
        }
        if let Some(name) = s.strip_prefix("session:") {
            if !name.is_empty() {
                return Ok(Capability::Session(name.to_string()));
            }
        }
        Ok(match s {
            "camera" => Capability::Camera,
            "microphone" => Capability::Microphone,
            "gps" => Capability::Gps,
            "cellular" => Capability::Cellular,
            "bluetooth" => Capability::Bluetooth,
            "nfc" => Capability::Nfc,
            "accelerometer" => Capability::Accelerometer,
            "gpu" => Capability::Gpu,
            "hardware_keystore" => Capability::HardwareKeystore,
            "lan_presence" => Capability::LanPresence,
            other => return Err(UnknownCapability(other.to_string())),
        })
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_strings() {
        for c in [
            Capability::Camera,
            Capability::HardwareKeystore,
            Capability::LocalData("photos".into()),
            Capability::Session("bank".into()),
        ] {
            let s = c.to_string();
            assert_eq!(s.parse::<Capability>().unwrap(), c);
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Capability>(&j).unwrap(), c);
        }
        assert!("local_data:".parse::<Capability>().is_err());
        assert!("teleporter".parse::<Capability>().is_err());
    }
}
