use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

use crate::{
    deques::GlobalArrDeque,
    utils::{ChannelThread, RelativeDirection},
};

const MONITOR_REORDER_BUFFER_LENGTH: usize = 10000;

struct CsvWriters<W: Write> {
    outgoing_writer: W,
    incoming_writer: W,
    outgoing_reorder_buffer: GlobalArrDeque<Option<Option<(u64, u64)>>>,
    incoming_reorder_buffer: GlobalArrDeque<Option<Option<(u64, u64)>>>,
}

pub(crate) struct MonitorPacketsThread {
    channel_thread: ChannelThread<RegisterPacketStatusCommand>,
}

struct RegisterPacketStatusCommand {
    direction: RelativeDirection,
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
    fn new(mut outgoing_writer: W, mut incoming_writer: W) -> Result<Self> {
        let header_line = b"seqno,tx_time,rx_time\n";
        outgoing_writer.write_all(header_line)?;
        incoming_writer.write_all(header_line)?;

        Ok(CsvWriters {
            outgoing_writer,
            incoming_writer,
            outgoing_reorder_buffer: GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(
                MONITOR_REORDER_BUFFER_LENGTH,
            ),
            incoming_reorder_buffer: GlobalArrDeque::<Option<Option<(u64, u64)>>>::new(
                MONITOR_REORDER_BUFFER_LENGTH,
            ),
        })
    }

    fn register_packet_status(&mut self, command: &RegisterPacketStatusCommand) {
        let (buffer, writer) = match command.direction {
            RelativeDirection::Outgoing => {
                (&mut self.outgoing_reorder_buffer, &mut self.outgoing_writer)
            }
            RelativeDirection::Incoming => {
                (&mut self.incoming_reorder_buffer, &mut self.incoming_writer)
            }
        };

        for _ in buffer.tail_index()..=command.seqno {
            if let Some((_popped_seqno, popped_cmd)) = buffer.push(None) {
                log::error!("Monitor packets reorder buffer filled!");
                assert!(popped_cmd.is_none());
                write_prefix(buffer, writer);
            }
        }
        // this can happen when the server has to retransmit the PacketStatus (dropped outgoing ack)
        if command.seqno >= buffer.head_index() {
            buffer[command.seqno] = Some(command.tx_rx_epoch_times);
        }
        write_prefix(buffer, writer);
    }

    fn flush(&mut self) -> Result<()> {
        self.outgoing_writer.flush()?;
        self.incoming_writer.flush()?;
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
        let outgoing_path = specific_dir.join("outgoing.csv");
        let incoming_path = specific_dir.join("incoming.csv");
        std::fs::create_dir_all(specific_dir)?;
        let outgoing_file = std::fs::File::create(outgoing_path)?;
        let incoming_file = std::fs::File::create(incoming_path)?;
        let outgoing_writer = BufWriter::new(outgoing_file);
        let incoming_writer = BufWriter::new(incoming_file);

        let mut monitor = CsvWriters::new(outgoing_writer, incoming_writer)?;

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
        direction: RelativeDirection,
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
mod test {
    use super::*;

    #[test]
    fn test_in_order_packets() {
        let outgoing_buf = Vec::new();
        let incoming_buf = Vec::new();
        let mut monitor = CsvWriters::new(outgoing_buf, incoming_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 1,
            tx_rx_epoch_times: None,
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Incoming,
            seqno: 0,
            tx_rx_epoch_times: Some((300, 400)),
        });

        monitor.flush().unwrap();

        let outgoing_output = String::from_utf8(monitor.outgoing_writer).unwrap();
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,0,0\n2,120,220\n";
        assert_eq!(outgoing_output, expected);
        let incoming_output = String::from_utf8(monitor.incoming_writer).unwrap();
        let expected_incoming = "seqno,tx_time,rx_time\n0,300,400\n";
        assert_eq!(incoming_output, expected_incoming);
    }

    #[test]
    fn test_out_of_order_packets() {
        let outgoing_buf = Vec::new();
        let incoming_buf = Vec::new();
        let mut monitor = CsvWriters::new(outgoing_buf, incoming_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 1,
            tx_rx_epoch_times: Some((110, 210)),
        });

        monitor.flush().unwrap();

        let outgoing_output = String::from_utf8(monitor.outgoing_writer).unwrap();
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,110,210\n2,120,220\n";
        assert_eq!(outgoing_output, expected);
    }

    #[test]
    fn test_gap_in_sequence() {
        let outgoing_buf = Vec::new();
        let incoming_buf = Vec::new();
        let mut monitor = CsvWriters::new(outgoing_buf, incoming_buf).unwrap();

        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 5,
            tx_rx_epoch_times: Some((150, 250)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 2,
            tx_rx_epoch_times: Some((120, 220)),
        });

        monitor.flush().unwrap();

        let outgoing_output = String::from_utf8(monitor.outgoing_writer).unwrap();
        // Only packet 0 should be written because packet 1 is missing, preventing 2+ from being written
        let expected = "seqno,tx_time,rx_time\n0,100,200\n";
        assert_eq!(outgoing_output, expected);
    }

    #[test]
    fn test_rtx() {
        let outgoing_buf = Vec::new();
        let incoming_buf = Vec::new();
        let mut monitor = CsvWriters::new(outgoing_buf, incoming_buf).unwrap();
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 1,
            tx_rx_epoch_times: Some((150, 250)),
        });
        monitor.register_packet_status(&RegisterPacketStatusCommand {
            direction: RelativeDirection::Outgoing,
            seqno: 0,
            tx_rx_epoch_times: Some((100, 200)),
        });
        monitor.flush().unwrap();

        let outgoing_output = String::from_utf8(monitor.outgoing_writer).unwrap();
        // Only packet 0 should be written because packet 1 is missing, preventing 2+ from being written
        let expected = "seqno,tx_time,rx_time\n0,100,200\n1,150,250\n";
        assert_eq!(outgoing_output, expected);
    }
}
