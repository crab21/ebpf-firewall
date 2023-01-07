#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
#[warn(unused_assignments)]
// external crate
// extern crate alloc;
use aya_bpf::{
    bindings::xdp_action,
    // helpers::bpf_redirect,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
mod bindings;
use aya_log_ebpf::{debug, error, info};
use bindings::{ethhdr, iphdr, tcphdr};
use core::{borrow::BorrowMut, mem, u8};
use ebpf_demo_common::PacketLog;
use memoffset::offset_of;

use crate::bindings::arphdr;

const IPPROTO_UDP: u8 = 0x0011;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMP: u8 = 1;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

#[xdp(name = "ebpf_demo")]
pub fn ebpf_demo(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(e) => xdp_action::XDP_PASS,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
// =======================
#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(256, 0);
#[map(name = "BLOCKLIST")] //
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(512, 0);

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, &'static str> {
    let mut action: u32;
    let source;
    let h_proto = u16::from_be(unsafe {
        *ptr_at_result(&ctx, offset_of!(ethhdr, h_proto))? //
    });

    if h_proto != ETH_P_IP {
        // info!(&ctx, "drop {}", h_proto);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_dest = u16::from_be(unsafe {
        *ptr_at_result(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
        //
    });

    if ip_dest == 22 {
        info!(&ctx, "SSH 22", ip_dest);
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_source = u16::from_be(unsafe {
        *ptr_at_result(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
        //
    });

    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });

    source = u32::from_be(unsafe { *ptr_at_result(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let destaddr =
        u32::from_be(unsafe { *ptr_at_result(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });
    if ip_proto == IPPROTO_UDP && (ip_source == 53 || ip_source == 5353) {
        return Ok(xdp_action::XDP_PASS);
    }

    if ip_proto != IPPROTO_TCP {
        info!(
            &ctx,
            &ctx, "not tcp: {} source: {}, dest:{}", ip_proto, ip_source, ip_dest
        );
        // TODO: drop
        action = xdp_action::XDP_DROP;
        // save_events(ctx, source, action);
        return Ok(xdp_action::XDP_DROP);
    }

    if ip_dest == 22 || ip_dest == 2022 || ip_dest == 3306 || ip_dest == 19092 || ip_dest == 6379 {
        debug!(
            &ctx,
            "SSH 2022 tcp: {} source: {}, dest:{}", ip_proto, ip_source, ip_dest
        );
        return Ok(xdp_action::XDP_PASS);
    }

    action = if (block_ip(source) || block_ip(destaddr) || (ip_dest >= 31024 && ip_dest <= 65000)) {
        xdp_action::XDP_PASS
    } else {
        // TODO: drop

        xdp_action::XDP_DROP
    };
    // save_events(
    //     &ctx,
    //     source,
    //     ip_source as u32,
    //     destaddr,
    //     ip_dest as u32,
    //     action,
    // );
    if action != xdp_action::XDP_PASS {
        return Ok(action);
    }

    if (ip_dest >= 1445 && ip_dest <= 1460) {
        action = xdp_action::XDP_PASS;
    }

    return Ok(action);
}

#[inline(always)] //
unsafe fn ptr_at_result<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, &'static str> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        error!(ctx, "offset error");
        return Err("offset error");
    }

    Ok((start + offset) as *const T)
}

fn save_events(
    ctx: &XdpContext,
    source: u32,
    source_port: u32,
    dst_addr: u32,
    d_port: u32,
    action: u32,
) {
    let log_entry = PacketLog {
        ipv4_address: source,
        source_port: source_port,
        dest_address: dst_addr,
        dest_port: d_port,
        action: action,
    };
    unsafe {
        EVENTS.output(ctx, &log_entry, 0); //
    }
    // info!(ctx, "{}-->{}", source_port, d_port);
}
