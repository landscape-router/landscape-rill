//! ts2021 服务端内嵌 DERP（REQ-068，TS2021_LEG §4）：TLS 同监听 `GET /derp`
//! 升级后按 node key 注册连接，SendPacket → 对端连接 RecvPacket 中继密文
//! （headscale 内嵌 DERP 同构）。协议帧对齐 tailscale derp/derp.go。

use super::Ts2021Server;
use crypto_box::aead::{Aead, Payload};
use crypto_box::{Nonce, SalsaBox};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::derp::{
    read_frame, write_frame, FRAME_CLIENT_INFO, FRAME_PING, FRAME_PONG, FRAME_RECV_PACKET,
    FRAME_SEND_PACKET, FRAME_SERVER_KEY,
};

/// 官方协议帧类型（接收侧遇到即忽略：客户端→服务端的辅助帧）
const FRAME_NOTE_PREFERRED_DERP: u8 = 0x07;
const FRAME_KEEP_ALIVE: u8 = 0x06;

/// 服务端 ping 周期（连接活性探测；客户端自动回 pong）
const PING_PERIOD: Duration = Duration::from_secs(30);

/// 会话表：node key → 出站帧通道（writer 任务单所有权写 socket）
pub type DerpHub = Arc<Mutex<HashMap<[u8; 32], mpsc::Sender<Vec<u8>>>>>;

/// DERP 会话服务（101 升级后调用）：问候 → ClientInfo（nacl box 持有证明）→ 中继循环
pub async fn serve_derp<IO>(mut io: IO, server: Arc<Ts2021Server>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 问候：magic(8) + 服务端公钥(32)
    let mut greeting = Vec::with_capacity(40);
    greeting.extend_from_slice(&super::DERP_MAGIC);
    greeting.extend_from_slice(&server.derp_pub);
    if let Err(e) = write_frame(&mut io, FRAME_SERVER_KEY, &greeting).await {
        debug!("[derp] greeting write failed: {e}");
        return;
    }
    // ClientInfo：clientPub(32) + nonce(24) + box(json)——解密成功 = 持有 node 私钥证明
    let (t, payload) = match read_frame(&mut io).await {
        Ok(v) => v,
        Err(e) => {
            debug!("[derp] client info read failed: {e}");
            return;
        }
    };
    if t != FRAME_CLIENT_INFO || payload.len() < 32 + 24 + 16 {
        debug!("[derp] malformed client info frame");
        return;
    }
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&payload[..32]);
    let box_ = SalsaBox::new(&crypto_box::PublicKey::from(client_pub), &server.derp_priv);
    let boxed_data = &payload[32..];
    let opened = box_.decrypt(
        Nonce::from_slice(&boxed_data[..24]),
        Payload {
            msg: &boxed_data[24..],
            aad: &[],
        },
    );
    if opened.is_err() {
        warn!("[derp] client info box open failed (not node key holder)");
        return;
    }
    // 注册会话：writer 任务持 socket 写半（通道 + ping 周期）
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    server.derp_hub.lock().unwrap().insert(client_pub, tx);
    info!(
        "[derp] session registered: node={}",
        crate::tailcfg::hex(&client_pub)
    );
    let (mut reader, mut writer) = tokio::io::split(io);
    let writer_client = client_pub;
    let writer_task = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_PERIOD);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                frame = rx.recv() => match frame {
                    Some(bytes) => {
                        if writer.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if write_frame(&mut writer, FRAME_PING, &rand::random::<[u8; 8]>())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    // 中继循环：SendPacket → 对端 RecvPacket；控制帧应答/忽略
    loop {
        let (t, payload) = match read_frame(&mut reader).await {
            Ok(v) => v,
            Err(_) => break,
        };
        match t {
            FRAME_SEND_PACKET if payload.len() > 32 => {
                let mut dst = [0u8; 32];
                dst.copy_from_slice(&payload[..32]);
                // RecvPacket 载荷 = 发送者 node key + 原密文（对端按源定位会话）
                let mut frame = Vec::with_capacity(payload.len());
                frame.extend_from_slice(&client_pub);
                frame.extend_from_slice(&payload[32..]);
                let delivered = server
                    .derp_hub
                    .lock()
                    .unwrap()
                    .get(&dst)
                    .is_some_and(|tx| tx.try_send(build_recv_frame(&frame)).is_ok());
                if !delivered {
                    debug!("[derp] drop packet: dst offline");
                }
            }
            FRAME_PING if payload.len() >= 8 => {
                let pong = payload[..8].to_vec();
                let _ = server
                    .derp_hub
                    .lock()
                    .unwrap()
                    .get(&client_pub)
                    .map(|tx| tx.try_send(build_pong_frame(&pong)));
            }
            FRAME_PING | FRAME_PONG | FRAME_KEEP_ALIVE | FRAME_NOTE_PREFERRED_DERP => {}
            other => debug!("[derp] ignored frame type {other:#x}"),
        }
    }
    server.derp_hub.lock().unwrap().remove(&writer_client);
    writer_task.abort();
    info!(
        "[derp] session closed: node={}",
        crate::tailcfg::hex(&writer_client)
    );
}

/// RecvPacket 整帧编码（写入通道的完整线上字节）
fn build_recv_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(FRAME_RECV_PACKET);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn build_pong_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(FRAME_PONG);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
