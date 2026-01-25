#!/usr/bin/env bash
set -e

tshark -r modbus_write_attack.pcap \
  -d tcp.port==502,mbtcp \
  -T fields \
  -e frame.time_utc \
  -e ip.src \
  -e ip.dst \
  -e modbus.func_code \
  -e modbus.reference_num \
  -e modbus.data
