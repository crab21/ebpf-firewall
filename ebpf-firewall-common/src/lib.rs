#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub source_port: u32,
    pub dest_address: u32,
    pub dest_port: u32,
    pub action: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendPorts {
    pub ports: [u32; 1],
    pub index: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {} //

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendPorts {}
