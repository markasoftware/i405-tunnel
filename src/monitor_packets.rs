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

struct CsvWriters<W: Write> {
    c2s_writer: W,
    s2c_writer: W,
    c2s_reorder_buffer: GlobalArrDeque<Option<Option<(u64, u64)>>>,
    s2c_reorder_buffer: GlobalArrDeque<Option<Option<(u64, u64)>>>,
}

pub(crate) struct MonitorPacketsThread {
    channel_thread: ChannelThread<RegisterPacketStatusCommand>,
}

struct RegisterPacketStatusCommand {
    direction: AbsoluteDirection,
    seqno: u64,
    /// None if the packet was dropped
    tx_rx_epoch_times: Option<(u64, u64)>,
}

fn write_prefix<W: Write>(
    reorder_buffer: &mut GlobalArrDeque<Option<Option<(u64, u64)>>>,
    writer: &mut W,
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

impl<W: Write> CsvWriters<W> {
    fn new(mut c2s_writer: W, mut s2c_writer: W) -> Result<Self> {
        let header_line = b"seqno,tx_time,rx_time\n";
        c2s_writer.write_all(header_line)?;
        s2c_writer.write_all(header_line)?;

        Ok(CsvWriters {
            c2s_writer,
            s2c_writer,
            c2s_reorder_buffer: GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(
                MONITOR_REORDER_BUFFER_LENGTH,
            ),
            s2c_reorder_buffer: GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(
                MONITOR_REORDER_BUFFER_LENGTH,
            ),
        })
    }

    fn register_packet_status(&mut self, command: &RegisterPacketStatusCommand) {
        let (buffer, writer) = match command.direction {
            AbsoluteDirection::C2S => (&mut self.c2s_reorder_buffer, &mut self.c2s_writer),
            AbsoluteDirection::S2C => (&mut self.s2c_reorder_buffer, &mut self.s2c_writer),
        };

        for _ in buffer.tail_index()..=command.seqno {
            if let Some((_popped_seqno, popped_cmd)) = buffer.push(None) {
                log::error!("Monitor packets reorder buffer filled!");
                assert!(popped_cmd.is_none());
                write_prefix(buffer, writer);
            }
        }
        // this can happen when the server has to retransmit the PacketStatus (dropped C2S ack)
        if command.seqno >= buffer.head_index() {
            buffer[command.seqno] = Some(command.tx_rx_epoch_times);
        }
        write_prefix(buffer, writer);
    }

    fn flush(&mut self) -> Result<()> {
        self.c2s_writer.flush()?;
        self.s2c_writer.flush()?;
        Ok(())
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
        let c2s_writer = BufWriter::new(c2s_file);
        let s2c_writer = BufWriter::new(s2c_file);

        let mut monitor = CsvWriters::new(c2s_writer, s2c_writer)?;

        let thread_fn = move || {
            while let Ok(command) = rx.recv() {
                monitor.register_packet_status(&command);
            }
            monitor.flush().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_packets() {
        let c2s_buf = Vec::new();
        let s2c_buf = Vec::new();
        let mut monitor = CsvWriters::new(c2s_buf, s2c_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 1,
            tx_rx_epoch_times: None,
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::S2C,
            seqno: 0,
            tx_rx_epoch_times: Some((300, 400)),
        });

        monitor.flush().unwrap();

        let c2s_output = String::from_utf8(monitor.c2s_writer).unwrap();
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,0,0\n2,120,220\n";
        assert_eq!(c2s_output, expected);
        let s2c_output = String::from_utf8(monitor.s2c_writer).unwrap();
        let expected_s2c = "seqno,tx_time,rx_time\n0,300,400\n";
        assert_eq!(s2c_output, expected_s2c);
    }

    #[test]
    fn test_out_of_order_packets() {
        let c2s_buf = Vec::new();
        let s2c_buf = Vec::new();
        let mut monitor = CsvWriters::new(c2s_buf, s2c_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 1,
            tx_rx_epoch_times: Some((110, 210)),
        });

        monitor.flush().unwrap();

        let c2s_output = String::from_utf8(monitor.c2s_writer).unwrap();
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,110,210\n2,120,220\n";
        assert_eq!(c2s_output, expected);
    }

    #[test]
    fn test_gap_in_sequence() {
        let c2s_buf = Vec::new();
        let s2c_buf = Vec::new();
        let mut monitor = CsvWriters::new(c2s_buf, s2c_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 5,
            tx_rx_epoch_times: Some((150, 250)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });

        monitor.flush().unwrap();

        let c2s_output = String::from_utf8(monitor.c2s_writer).unwrap();
        // Only packet 0 should be written because packet 1 is missing, preventing 2+ from being written
        let expected = "seqno,tx_time,rx_time\n0,100,200\n";
        assert_eq!(c2s_output, expected);
    }

    #[test]
    fn test_rtx() {
        let c2s_buf = Vec::new();
        let s2c_buf = Vec::new();
        let mut monitor = CsvWriters::new(c2s_buf, s2c_buf).unwrap();
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 1,
            tx_rx_epoch_times: Some((150, 250)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: AbsoluteDirection::C2S,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.flush().unwrap();

        let c2s_output = String::from_utf8(monitor.c2s_writer).unwrap();
        // Only packet 0 should be written because packet 1 is missing, preventing 2+ from being written
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,150,250\n";
        assert_eq!(c2s_output, expected);
    }
}
