use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

use crate::{
    deques::GlobalArrDeque,
    utils::{AbsoluteDirection, ChannelThread},
};

const MONITOR_REORDER_BUFFER_LENGTH: usize = 10000;

pub(crate) struct MonitorPacketsThread {
    channel_thread: ChannelThread<RegisterPacketStatusCommand>,
}

struct RegisterPacketStatusCommand {
    direction: AbsoluteDirection,
    seqno: u64,
    /// None if the packet was dropped
    tx_rx_epoch_times: Option<(u64, u64)>,
}

fn write_prefix(
    reorder_buffer: &mut GlobalArrDeque<Option<Option<(u64, u64)>>>,
    writer: &mut BufWriter<std::fs::File>,
) {
    while reorder_buffer.len() > 0 && reorder_buffer[reorder_buffer.head_index()].is_some() {
        let (seqno, tx_rx_epoch_times) = reorder_buffer.pop();
        let tx_rx_epoch_times = tx_rx_epoch_times.unwrap().unwrap_or((0, 0));
        let line = format!(
            "{},{},{}\n",
            seqno, tx_rx_epoch_times.0, tx_rx_epoch_times.1
        );
        writer
            .write_all(line.as_bytes())
            .expect("Failed to write packet status to file");
    }
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
        let header_line = b"seqno,tx_time,rx_time\n";
        c2s_writer.write_all(header_line)?;
        s2c_writer.write_all(header_line)?;

        let mut c2s_reorder_buffer =
            GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(MONITOR_REORDER_BUFFER_LENGTH);
        let mut s2c_reorder_buffer =
            GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(MONITOR_REORDER_BUFFER_LENGTH);

        let thread_fn = move || {
            while let Ok(command) = rx.recv() {
                let (buffer, writer) = match command.direction {
                    AbsoluteDirection::C2S => (&mut c2s_reorder_buffer, &mut c2s_writer),
                    AbsoluteDirection::S2C => (&mut s2c_reorder_buffer, &mut s2c_writer),
                };
                for _ in buffer.tail_index()..=command.seqno {
                    if let Some((_popped_seqno, popped_cmd)) = buffer.push(None) {
                        log::error!("Monitor packets reorder buffer filled!");
                        assert!(popped_cmd.is_none()); // because we always get rid of prefixes
                        write_prefix(buffer, writer);
                    }
                    buffer[command.seqno] = Some(command.tx_rx_epoch_times);
                }
                write_prefix(buffer, writer);
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
