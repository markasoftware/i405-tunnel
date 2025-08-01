use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

use crate::utils::{AbsoluteDirection, ChannelThread};

pub(crate) struct MonitorPacketsThread {
    channel_thread: ChannelThread<RegisterPacketStatusCommand>,
}

struct RegisterPacketStatusCommand {
    direction: AbsoluteDirection,
    seqno: u64,
    /// None if the packet was dropped
    tx_rx_epoch_times: Option<(u64, u64)>,
}

impl MonitorPacketsThread {
    pub(crate) fn spawn(dir: PathBuf) -> Result<MonitorPacketsThread> {
        let (tx, rx) = mpsc::channel::<RegisterPacketStatusCommand>();
        let specific_dir = dir.join(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_string(),
        );
        let c2s_path = specific_dir.join("client_to_server.csv");
        let s2c_path = specific_dir.join("server_to_client.csv");
        std::fs::create_dir_all(specific_dir)?;
        let c2s_file = std::fs::File::create(c2s_path)?;
        let s2c_file = std::fs::File::create(s2c_path)?;
        let mut c2s_writer = BufWriter::new(c2s_file);
        let mut s2c_writer = BufWriter::new(s2c_file);
        let header_line = b"seqno,tx_time,rx_time";
        c2s_writer.write_all(header_line)?;
        s2c_writer.write_all(header_line)?;

        let thread_fn = move || {
            let mut last_seqno = None;
            'command_loop: while let Ok(command) = rx.recv() {
                if last_seqno.is_some_and(|last_seqno| command.seqno <= last_seqno) {
                    log::warn!(
                        "Tried to log packet status for the same packet multiple times -- retransmision?"
                    );
                    continue 'command_loop;
                }
                last_seqno = Some(command.seqno);

                let (tx_time, rx_time) = command.tx_rx_epoch_times.unwrap_or((0, 0));
                let line = format!("{},{},{}", command.seqno, tx_time, rx_time);
                let writer = match command.direction {
                    AbsoluteDirection::C2S => &mut c2s_writer,
                    AbsoluteDirection::S2C => &mut s2c_writer,
                };
                writer
                    .write_all(line.as_bytes())
                    .expect("Failed to write packet status to file");
            }
            c2s_writer.flush().unwrap();
            s2c_writer.flush().unwrap();
        };

        Ok(MonitorPacketsThread {
            channel_thread: ChannelThread::spawn(tx, thread_fn),
        })
    }

    pub(crate) fn register_packet_status(
        &self,
        direction: AbsoluteDirection,
        seqno: u64,
        tx_rx_epoch_times: Option<(u64, u64)>,
    ) {
        self.channel_thread
            .tx()
            .send(RegisterPacketStatusCommand {
                direction,
                seqno,
                tx_rx_epoch_times,
            })
            .unwrap();
    }
}
