#!/bin/bash
sudo ovs-vsctl \
  -- --id=@p1 get port s1-eth1 \
  -- --id=@p2 get port s1-eth2 \
  -- --id=@p3 get port s1-eth3 \
  -- --id=@p4 get port s1-eth4 \
  -- --id=@p5 get port s1-eth5 \
  -- --id=@p6 get port s1-eth6 \
  -- --id=@p7 get port s1-eth7 \
  -- --id=@m create mirror name=modbus-mirror select-src-port=@p1,@p2,@p3,@p4,@p5,@p7 select-dst-port=@p1,@p2,@p3,@p4,@p5,@p7 output-port=@p6 \
  -- set bridge s1 mirrors=@m
