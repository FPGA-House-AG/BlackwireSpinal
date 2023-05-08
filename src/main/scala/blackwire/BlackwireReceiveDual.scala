package blackwire

import spinal.core._
import spinal.lib._

import spinal.lib.bus.misc._
import spinal.lib.bus.amba4.axi._

import scala.math._

import corundum._

// companion object
object BlackwireReceiveDual {
  val busconfig = Axi4Config(15, 32, 2, useLock = false, useQos = false, useRegion = false)
  def main(args: Array[String]) : Unit = {
    val vhdlReport = Config.spinal.generateVhdl(new BlackwireReceiveDual(busconfig, ClockDomain.current))
    val verilogReport = Config.spinal.generateVerilog(new BlackwireReceiveDual(busconfig, ClockDomain.current))
    //vhdlReport.mergeRTLSource("merge")
  }
}

case class BlackwireReceiveDual(busCfg : Axi4Config, cryptoCD : ClockDomain, has_busctrl : Boolean = true, include_chacha : Boolean = true, use_async : Boolean = true) extends Component {
  final val corundumDataWidth = 512
  final val cryptoDataWidth = 128
  final val maxPacketLength = 1534
  final val peer_num = 256/*maximum number of peers*/
  final val keys_num = 4/*sessions per peers*/ * peer_num

  // 1534 rounded up 2048/(512/8) == 32

  final val session_addr_width = LookupTableAxi4.slave_width(16, keys_num, busCfg)
  println("session_addr_width = " + session_addr_width)
  final val rxkey_addr_width = LookupTableAxi4.slave_width(256, keys_num, busCfg)
  println("rxkey_addr_width = " + rxkey_addr_width)

  val sessionSlaveCfg = busCfg.copy(addressWidth = session_addr_width)
  val rxkeySlaveCfg = busCfg.copy(addressWidth = rxkey_addr_width)

  val io = new Bundle {
    // I/O is the Corundum Frame AXIS tdata/tkeep/tuser format payload
    val sink = slave Stream Fragment(CorundumFrame(corundumDataWidth))
    val source = master Stream Fragment(CorundumFrame(corundumDataWidth))

    val source_handshake = master Stream Fragment(CorundumFrame(corundumDataWidth))
    val ctrl_session = slave(Axi4(sessionSlaveCfg))
    val ctrl_rxkey = slave(Axi4(rxkeySlaveCfg))
    // IP address lookup
    val source_ipl = master Flow Bits(32 bits)
    val sink_ipl = slave Flow UInt(11 bits)
  }

  io.sink.addAttribute("mark_debug")
  io.source.addAttribute("mark_debug")

  // to measure latencies in simulation
  val cycle = Reg(UInt(32 bits)).init(0)
  cycle := cycle + 1

  // x is TDATA+TKEEP Ethernet frame from Corundum
  val x = Stream Fragment(CorundumFrame(corundumDataWidth))
  x << io.sink.s2mPipe().m2sPipe()

  // fork x into two streams, Wireguard Type4 and other packet
  val type4_demux = new CorundumFrameDemuxWireguardType4(corundumDataWidth)
  type4_demux.io.sink << x

  // non-Type 4 packets are routed here
  val dropOnFull = CorundumFrameDrop(corundumDataWidth)
  val readerStash = CorundumFrameStash(corundumDataWidth, fifoSize = 32)
  dropOnFull.io.sink << type4_demux.io.source_other
  readerStash.io.sink << dropOnFull.io.source 
  dropOnFull.io.drop := (readerStash.io.availability < 2)
  io.source_handshake << readerStash.io.source

  // Type 4 packets go into stash (@TODO why? really needed?)
  val stash = CorundumFrameStash(corundumDataWidth, fifoSize = 32)
  stash.io.sink << type4_demux.io.source_type4

  // y is stash output but in TDATA+length format
  val y = Stream(Fragment(Bits(corundumDataWidth bits)))
  val fff = Fragment(Bits(corundumDataWidth bits))
  fff.last := stash.io.source.payload.last
  fff.fragment := stash.io.source.payload.fragment.tdata
  y <-< stash.io.source.translateWith(fff)
  val y_length = RegNextWhen(stash.io.length, y.ready)

  // yy is with Ethernet, IPv4 and UDP headers removed, thus the Type 4 packet
  val yy = Stream(Fragment(Bits(corundumDataWidth bits)))

  val headers = AxisExtractHeader(corundumDataWidth, 14 + 20 + 8)
  headers.io.sink << y
  headers.io.sink_length := y_length
  yy << headers.io.source
  val yy_length = headers.io.source_length
  val yy_header =
    yy.payload.fragment(4 * 8, 32 bits).resize(log2Up(peer_num)) ##
    headers.io.header((14 + 12) * 8, 32 bits).subdivideIn(8 bits).reverse.asBits ##
    headers.io.header((14 + 20) * 8, 16 bits).subdivideIn(8 bits).reverse.asBits

  // lookup the given peer session on yy, for yyy
  val session_lookup = yy.firstFire
  val session_addr = U(yy.payload.fragment(4*8, 32 bits).resize(log2Up(keys_num)))
  val session_random = Bits(16 bits)

  (!has_busctrl) generate new Area {
    val lut = LookupTable(16/*bits*/, keys_num)

    lut.mem.initBigInt(Seq.tabulate(keys_num)(i => BigInt(i)))

    lut.io.portA.en := True
    lut.io.portA.wr := False
    lut.io.portA.wrData := 0
    lut.io.portA.addr := session_addr
    session_random := lut.io.portA.rdData
    lut.io.portB.en := True
    lut.io.portB.wr := False
    lut.io.portB.wrData := 0
    lut.io.portB.addr := 0
  }
  (has_busctrl) generate new Area {
    val lut = LookupTableAxi4(16/*bits*/, keys_num, busCfg)
    lut.mem.mem.initBigInt(Seq.tabulate(keys_num)(i => BigInt(i)))
    lut.io.en := True
    lut.io.wr := False
    lut.io.wrData := 0
    lut.io.addr := session_addr
    session_random := lut.io.rdData
    lut.io.ctrlbus << io.ctrl_session
  }

  // yyy is yy 2 cycles delayed to match session lookup latency
  val yyy = Stream(Fragment(Bits(corundumDataWidth bits)))
  yyy <-< yy.stage()
  val yyy_length = Delay(yy_length, 2, yy.ready)
  val yyy_header= Delay(yy_header, 2, yy.ready)
  val session_result = Delay(session_lookup, cycleCount = 2, init = False)
  // 0000000000000007.59250001.00000004 [0]
  //                  ====[16]
  val receiver_remainder = yyy.payload.fragment(4 * 8, 32 bits) >> 16/*TODO calc*/
  val session_valid = (session_random === receiver_remainder)

  yy.addAttribute("mark_debug")
  session_lookup.addAttribute("mark_debug")
  session_addr  .addAttribute("mark_debug")
  session_random.addAttribute("mark_debug")
  receiver_remainder.addAttribute("mark_debug")
  session_valid.addAttribute("mark_debug")

  // w is yyy but fragment bit 0 is drop flag, bit 1 is crypto flow
  val w = Stream(Fragment(Bits(corundumDataWidth bits)))
  val w_length = yyy_length
  val w_header = yyy_header
  w << yyy
  // store drop flag in bit 0 of Type 4 header
  when (yyy.firstFire) {
    w.payload.fragment(0) := !session_valid
  }
  // after each packet in w, select the flow that is most empty
  val flow_most_empty = Reg(UInt(1 bits)) init(0)
  val mux_select = Reg(UInt(1 bits)) init(0)
  when (yyy.lastFire) {
    //mux_select := flow_most_empty // arbiter
    // := 1 - mux_select // ping-pong
    mux_select := 0 // fixed
  }
  // store chosen crypto flow in bit 1 of Type 4 header
  when (yyy.firstFire) {
    w.payload.fragment(1) := (mux_select === 1)
  }

  val endpoint_fifos = Array.fill(2) { StreamFifo(Bits(log2Up(peer_num) + 16 + 32 bits), 512/*keys in FIFO*/) }
  // push in correct FIFO only for non-dropped packets
  endpoint_fifos(0).io.push.valid := (w.firstFire & (w.payload.fragment(1 downto 0) === B"00"))
  endpoint_fifos(1).io.push.valid := (w.firstFire & (w.payload.fragment(1 downto 0) === B"10"))
  // bring peer and endpoint IPv4 address and UDP port to replay prevent
  endpoint_fifos(0).io.push.payload := w_header
  endpoint_fifos(1).io.push.payload := w_header

  val rxkey = Bits(256 bits)
  // lookup TX key for non-dropped packets only
  val rxkey_lookup = w.firstFire && !w.payload.fragment(0)
  val rxkey_lut_address = U(w.payload.fragment(4 * 8, 32 bits).resize(log2Up(keys_num)))
  //rxkey_lookup.addAttribute("mark_debug")
  //rxkey_lut_address.addAttribute("mark_debug")
  val rxkey_fifos = Array.fill(2) { StreamFifo(Bits(256 bits), 8/*keys in FIFO*/) }
  // bring session and nonce to replay prevent
  val nonce_fifos = Array.fill(2) { StreamFifo(Bits(log2Up(keys_num) + 64 bits), 512/*nonces in FIFO*/) }

  (!has_busctrl) generate new Area {
    val rxkey_lut = LookupTable(256/*bits*/, keys_num)
    rxkey_lut.mem.initBigInt(Seq.fill(keys_num)(BigInt("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f".split(" ").reverse.mkString(""), 16)))
    //rxkey_lut.mem.initBigInt(Seq.tabulate(keys_num)(i => BigInt(i)))
    rxkey_lut.io.portA.en := rxkey_lookup
    rxkey_lut.io.portA.wr := False
    rxkey_lut.io.portA.wrData := 0
    rxkey_lut.io.portA.addr := rxkey_lut_address
    rxkey_lut.io.portB.en := False
    rxkey_lut.io.portB.wr := False
    rxkey_lut.io.portB.wrData := 0
    rxkey_lut.io.portB.addr := 0
    rxkey := rxkey_lut.io.portA.rdData.subdivideIn(8 bits).reverse.asBits
  }
  // TX key lookup and update via bus controller
  (has_busctrl) generate new Area {
    val rxkey_lut = LookupTableAxi4(256/*bits*/, keys_num, busCfg)
    rxkey_lut.mem.mem.initBigInt(Seq.fill(keys_num)(BigInt("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f".split(" ").reverse.mkString(""), 16)))
    rxkey_lut.io.en := rxkey_lookup
    rxkey_lut.io.wr := False
    rxkey_lut.io.wrData := 0
    rxkey_lut.io.addr := rxkey_lut_address
    rxkey := rxkey_lut.io.rdData.subdivideIn(8 bits).reverse.asBits
    rxkey_lut.io.ctrlbus << io.ctrl_rxkey
  }
  val rxkey_thumbnail = rxkey(255 downto 248) ## rxkey(7 downto 0)
  val rxkey_mux = Delay(w.payload.fragment(1), cycleCount = 2, w.ready)
  //rxkey.addAttribute("mark_debug")
  //rxkey_thumbnail.addAttribute("mark_debug")
  // push looked-up (latency 2 cycles) TX keys into key_fifo
  val rxkey_result = Delay(rxkey_lookup, cycleCount = 2, init = False)

  rxkey_fifos.zipWithIndex.foreach {
    case (rxkey_fifo, index) => {
      rxkey_fifos(index).io.push.valid   := rxkey_result && (rxkey_mux.asUInt === index)
      rxkey_fifos(index).io.push.payload := rxkey
    }
  }

  val www = Stream(Fragment(Bits(corundumDataWidth bits)))
  www <-< w.stage()
  val www_length = Delay(w_length, 2, w.ready)

  // push nonces in fifos, required later by Replay Prevent
  nonce_fifos.zipWithIndex.foreach {
    case (nonce_fifo, index) => {
      nonce_fifos(index).io.push.valid   := www.firstFire && (www.payload.fragment(1).asUInt === index)
      nonce_fifos(index).io.push.payload := www.payload.fragment(63 downto 32).subdivideIn(4 slices).reverse.asBits.resize(log2Up(keys_num)) ## www.payload.fragment((4 + 4) * 8, 64 bits)
    }
  }

  val v = Stream Fragment(CorundumFrame(corundumDataWidth))
  val in_corundum = AxisToCorundumFrame(corundumDataWidth)
  in_corundum.io.sink << www
  in_corundum.io.sink_length := www_length
  in_corundum.io.sink_drop := www.firstFire && www.fragment(0)
  v << in_corundum.io.source
  
  val instash = CorundumFrameFlowStash(corundumDataWidth, fifoSize = 32, 24)
  instash.io.sink << v

  val vv = Stream Fragment(CorundumFrame(corundumDataWidth))

  vv <-< instash.io.source
  val flow_from_pkt = instash.io.source.payload.fragment.tdata(1)
  val vv_mux_sel = RegNextWhen(flow_from_pkt, instash.io.source.firstFire)

  val crypto_areas = Array.tabulate(2)(instanceNr => {
    new Area {
      val sink = Stream Fragment(CorundumFrame(corundumDataWidth))
      val source = Stream Fragment(CorundumFrame(corundumDataWidth))
      val rxkey_sink = Stream(Bits(256 bits))
      // higher clock rate for crypto
      val crypto_turbo = new ClockingArea(cryptoCD) {
        val decrypt = BlackwireDecryptPipe(busCfg, instanceNr)
      }
      // Approach 1, SpinalHDL BlackBox wrappers around axis_async_fifo.v
      // The benefit is that axis_async_fifo.tcl should generate the correct timing constraints

      // @NOTE @TODO For synthesis, use this axis_async_fifo
      if (use_async) {
        val ccfifo_rxkey = KeyStreamCC    (128, ClockDomain.current/*push*/, cryptoCD/*pop*/)
        val ccfifo_crypt = CorundumFrameCC(128, ClockDomain.current/*push*/, cryptoCD/*pop*/)
        val ccfifo_plain = CorundumFrameCC(128, cryptoCD/*push*/, ClockDomain.current/*pop*/)

        // skid buffers in slowest clock domain
        ccfifo_rxkey.io.push                                        << rxkey_sink
        ccfifo_rxkey.io.pop                                         >> crypto_turbo.decrypt.io.rxkey_sink
                                       
        ccfifo_crypt.io.push                                        << sink
        ccfifo_crypt.io.pop                                         >> crypto_turbo.decrypt.io.sink
                                       
        ccfifo_plain.io.push                                        << crypto_turbo.decrypt.io.source
        ccfifo_plain.io.pop                                         >> source
        printf("--- Using axis_async_fifo ---\n")
      }
      // @NOTE @TODO For GHDL simulation, use this axis_async_fifo:
      if (!use_async) {
        val ccfifo_rxkey = StreamFifoCC(                            Bits(256 bits), 128, ClockDomain.current/*push*/, cryptoCD/*pop*/)
        val ccfifo_crypt = StreamFifoCC(Fragment(CorundumFrame(corundumDataWidth)), 128, ClockDomain.current/*push*/, cryptoCD/*pop*/)
        val ccfifo_plain = StreamFifoCC(Fragment(CorundumFrame(corundumDataWidth)), 128, cryptoCD/*push*/, ClockDomain.current/*pop*/)

        // skid buffers in slowest clock domain
        ccfifo_rxkey.io.push                                        << rxkey_sink
        ccfifo_rxkey.io.pop                                         >> crypto_turbo.decrypt.io.rxkey_sink
                                       
        ccfifo_crypt.io.push                                        << sink
        ccfifo_crypt.io.pop                                         >> crypto_turbo.decrypt.io.sink
                                       
        ccfifo_plain.io.push                                        << crypto_turbo.decrypt.io.source
        ccfifo_plain.io.pop                                         >> source
        printf("--- Using StreamFifoCC instead of axis_async_fifo ---\n")
      }

      // Variation of StreamFifoCC:
      // queue(depth, pushCD, popCD) uses StreamFifoCC (a cross-clocking FIFO)
      //
      //crypto_turbo.decrypt.io.rxkey_sink << rxkey_sink.queue(8, ClockDomain.current/*push*/, cryptoCD)
      //crypto_turbo.decrypt.io.sink       << sink      .queue(8, ClockDomain.current/*push*/, cryptoCD)
      //source << crypto_turbo.decrypt.io.source.queue(8, cryptoCD/*push*/, ClockDomain.current/*pop*/)
    }
  })

  val crypto_sinks = Array.fill(2) { Stream Fragment(CorundumFrame(corundumDataWidth)) }

  Vec(crypto_sinks(0), crypto_sinks(1)) <> StreamDemux(
    vv,
    U(vv_mux_sel),
    2
  )
  crypto_areas(0).sink << crypto_sinks(0).s2mPipe().m2sPipe().s2mPipe().m2sPipe()
  crypto_areas(1).sink << crypto_sinks(1).s2mPipe().m2sPipe().s2mPipe().m2sPipe()

  crypto_areas(0).rxkey_sink << rxkey_fifos(0).io.pop.s2mPipe().m2sPipe().s2mPipe().m2sPipe()
  crypto_areas(1).rxkey_sink << rxkey_fifos(1).io.pop.s2mPipe().m2sPipe().s2mPipe().m2sPipe()

  // fragment (packet) aware multiplexer, gather packets from both crypto flows
  val crypto_mux = StreamArbiterFactory().roundRobin.build(Fragment(CorundumFrame(corundumDataWidth)), 2)
  crypto_mux.io.inputs(0) << crypto_areas(0).source.s2mPipe().m2sPipe().s2mPipe().m2sPipe()
  crypto_mux.io.inputs(1) << crypto_areas(1).source.s2mPipe().m2sPipe().s2mPipe().m2sPipe()
  val r = Stream Fragment(CorundumFrame(corundumDataWidth))
  r << crypto_mux.io.output
  val r_crypto_flow = crypto_mux.io.chosen

  // go from 1 to 2 user bits, register staged
  val rr = Stream Fragment(CorundumFrame(corundumDataWidth, userWidth = 2))
  rr.payload.tdata := RegNextWhen(r.payload.tdata, r.ready)
  rr.payload.tkeep := RegNextWhen(r.payload.tkeep, r.ready)
  rr.payload.tuser(0) := RegNextWhen(r.payload.tuser(0), r.ready)
  rr.payload.tuser(1) := RegNextWhen(crypto_mux.io.chosen.asBool, r.ready)
  rr.valid := RegNextWhen(r.valid, r.ready)
  rr.last := RegNextWhen(r.last, r.ready)
  r.ready := rr.ready

  val rr_nonce = Mux(rr.payload.tuser(1), nonce_fifos(1).io.pop.payload, nonce_fifos(0).io.pop.payload)
  nonce_fifos.zipWithIndex.foreach {
    case (nonce_fifo, index) => {
      nonce_fifos(index).io.pop.ready := rr.firstFire && (rr.payload.tuser(1).asUInt === index)
    }
  }

  val rr_endpoint = Mux(rr.payload.tuser(1), endpoint_fifos(1).io.pop.payload, endpoint_fifos(0).io.pop.payload)
  endpoint_fifos.zipWithIndex.foreach {
    case (endpoint_fifo, index) => {
      endpoint_fifos(index).io.pop.ready := rr.firstFire && (rr.payload.tuser(1).asUInt === index)
    }
  }

  // lookup peer that belongs to this source IP address
  val ip_addr = rr.payload.fragment.tdata(12 * 8, 32 bits).subdivideIn(8 bits).reverse.asBits
  val ip_addr_lookup = rr.firstFire
  io.source_ipl.valid := RegNext(ip_addr_lookup)
  io.source_ipl.payload := RegNext(ip_addr)

  // delay as much as the lookup takes
  val rrr = Stream Fragment(CorundumFrame(corundumDataWidth, userWidth = 2))
  val lal = StreamLatency(Fragment(CorundumFrame(corundumDataWidth, userWidth = 2)), 65)
  lal.io.sink << rr
  rrr << lal.io.source
  val rrr_endpoint = io.sink_ipl.payload

  val ethhdr = CorundumFrameInsertHeader(corundumDataWidth, userWidth = 2, 14)
  ethhdr.io.sink << rrr
  ethhdr.io.header := B("112'x000a3506a3beaabbcc2222220800").subdivideIn(8 bits).reverse.asBits
  val h = Stream Fragment(CorundumFrame(corundumDataWidth, userWidth = 2))
  h << ethhdr.io.source

  val fcs = CorundumFrameAppendTailer(corundumDataWidth, userWidth = 2, 4)
  fcs.io.sink << h
  val f = Stream Fragment(CorundumFrame(corundumDataWidth, userWidth = 2))
  f << fcs.io.source

  // go from 2 to 1 user bits
  val ff = Stream Fragment(CorundumFrame(corundumDataWidth, userWidth = 1))
  ff.payload.tdata := f.payload.tdata
  ff.payload.tkeep := f.payload.tkeep
  ff.payload.tuser(0) := f.payload.tuser(0)
  ff.valid := f.valid
  ff.last := f.last
  f.ready := ff.ready

  io.source << ff

  //printf("x to r = %d clock cycles.\n", LatencyAnalysis(x.valid, r.valid))

  // Execute the function renameAxiIO after the creation of the component
  addPrePopTask(() => CorundumFrame.renameAxiIO(io))
}

import spinal.sim._
import spinal.core.sim._
import scala.util.Random

object BlackwireReceiveDualSim {
  def main(args: Array[String]) : Unit = {
    val dataWidth = 512
    val maxDataValue = scala.math.pow(2, dataWidth).intValue - 1
    val keepWidth = dataWidth/8
    val include_chacha = true

    SimConfig
    // GHDL can simulate VHDL, required for ChaCha20Poly1305
    .withGhdl.withWave
    //.withFstWave
    //.addRunFlag support is now in SpinalHDL dev branch
    .addRunFlag("--unbuffered") //.addRunFlag("--disp-tree=inst")
    .addRunFlag("--ieee-asserts=disable").addRunFlag("--assert-level=none")
    .addRunFlag("--backtrace-severity=warning")
    
    //.withXSim.withXilinxDevice("xcu50-fsvh2104-2-e")
    //.addSimulatorFlag("--ieee=standard")
    //.addSimulatorFlag("-v")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unisim/v93")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unimacro/v93") 
    // these define bus_pkg and bus_pkg1

//    .addRtl(s"../ChaCha20Poly1305/src/ChaCha20.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/AEAD_ChaCha_Poly.vhd")
//
//    .addRtl(s"../ChaCha20Poly1305/src/q_round.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/diag_round.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/col_round.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/half_round.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/test_top_ChaCha.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/Poly1305.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/ChaCha20_128.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul136_mod_red.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul_red_pipeline.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/test_top_mod_red.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/ChaCha_int.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/r_power_n.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul_gen_0.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul_36.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul_72.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mul_144.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/mod_red_1305.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/Poly_1305_pipe_top.vhd")
//    //.addRtl(s"../ChaCha20Poly1305/src/test_top_Poly.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/Poly_1305_pipe.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/AEAD_decryption_top.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/AEAD_top.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/Poly_pipe_top_test.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/AEAD_decryption.vhd")
//    .addRtl(s"../ChaCha20Poly1305/src/AEAD_decryption_wrapper.vhd")
//    //.addRtl(s"../ChaCha20Poly1305/src/convert/aead_decryption_wrapper.v")

    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/bus_pkg1.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/AEAD_decryption_wrapper_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/AEAD_decryption_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/ChaCha20_128.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/ChaCha_int.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/col_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/diag_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/half_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mod_red_1305.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_136_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul136_mod_red.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_36.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_68_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_red_pipeline.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/Poly_1305_pipe_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/Poly_1305_pipe_top_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/q_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/r_pow_n_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_gen_0.vhd")

    //.addRtl(s"../corundum.rx.tx/fpga/lib/eth/lib/axis/rtl/axis_async_fifo.v")

    .compile {
      val dut = new BlackwireReceiveDual(BlackwireReceiveDual.busconfig, cryptoCD = ClockDomain.current, include_chacha = include_chacha, use_async = false)
      //dut.with_chacha.decrypt.io.sink.ready.simPublic()
      //dut.with_chacha.decrypt.io.sink.valid.simPublic()
      //dut.with_chacha.decrypt.io.sink.last.simPublic()
      //dut.with_chacha.decrypt.io.source.ready.simPublic()
      //dut.with_chacha.decrypt.io.source.valid.simPublic()
      //dut.with_chacha.decrypt.io.source.last.simPublic()
      //dut.with_chacha.decrypt.io.tag_valid.simPublic()
      //dut.with_chacha.decrypt.io.tag_pulse.simPublic()
      dut
    }
    //.addSimulatorFlag("-Wno-TIMESCALEMOD")
    // include_chacha = true requires GHDL or XSim
    .doSim { dut =>

      SimTimeout(10000)

      dut.io.sink.valid #= false

      //Fork a process to generate the reset and the clock on the dut
      dut.clockDomain.forkStimulus(period = 10)

      //ClockDomain(dut.io.coreClk, dut.io.coreReset).forkStimulus(10)

      var data0 = 0

      var last0 = false
      var valid0 = false
      var tkeep0 = BigInt(0)
      var pause = false

      dut.io.sink.valid #= valid0
      dut.io.sink.payload.tdata #= 0
      dut.io.sink.last #= last0
      dut.io.sink.payload.tkeep #= tkeep0
      dut.io.sink.payload.tuser #= 0

      dut.io.source.ready #= false

      dut.clockDomain.waitSampling()

      val backpressureThread = fork {
        while (true) {
          dut.io.source.ready #= true //(Random.nextInt(100) > 95)
          dut.clockDomain.waitSampling()
        }
      }

// "0102030405060102030405060102" Ethernet
// "xxxx11887766554433221145" IPv4, IHL=5, protocol=0x11 (UDP)
// "0000FF0000000000000000FF"
// "CCCCLLLLb315SSSS", DDDD=port 5555 (0x15b3)
// "00000000FFFF0000"


      val packet_contents = Vector(
        // RFC7539 2.8.2. Example and Test Vector for AEAD_CHACHA20_POLY1305
        // but with zero-length AAD, and Wireguard 64-bit nonce
        Vector(
          //      <-------- Ethernet header --------------> <-IPv4 header IHL=5 protocol=0x11->                         <--5555,5555,len0x172-> <-WG Type4> <receiver#> <-- Wireguard NONCE --> <L  a  d  i  e  s
          BigInt("01 02 03 04 05 06 01 02 03 04 05 06 08 00 45 11 22 33 44 55 66 77 88 11 00 00 A1 A2 A3 A4 B1 B2 B3 B4 15 b3 15 b3 01 72 00 00 04 00 00 00 00 01 00 01 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89".split(" ").reverse.mkString(""), 16),
          BigInt("46 d6 f4 04 2a 8e 38 4e f4 bd 2f bc 73 30 b8 be 55 eb 2d 8d c1 8a aa 51 d6 6a 8e c1 f8 d3 61 9a 25 8d b0 ac 56 95 60 15 b7 b4 93 7e 9b 8e 6a a9 57 b3 dc 02 14 d8 03 d7 76 60 aa bc 91 30 92 97".split(" ").reverse.mkString(""), 16),
          BigInt("1d a8 f2 07 17 1c e7 84 36 08 16 2e 2e 75 9d 8e fc 25 d8 d0 93 69 90 af 63 c8 20 ba 87 e8 a9 55 b5 c8 27 4e f7 d1 0f 6f af d0 46 47 1b 14 57 76 ac a2 f7 cf 6a 61 d2 16 64 25 2f b1 f5 ba d2 ee".split(" ").reverse.mkString(""), 16),
          BigInt("98 e9 64 8b b1 7f 43 2d cc e4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 0 byte WG payload, tag match
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-------- Ethernet header --------------> <-IPv4 header IHL=5 protocol=0x11->                         <--5555,5555,len0x172-> <-WG Type4> <receiver#> <-- Wireguard NONCE --> <- Poly 1305 Tag
          BigInt("01 02 03 04 05 06 01 02 03 04 05 06 08 00 45 11 22 33 44 55 66 77 88 11 00 00 A1 A2 A3 A4 B1 B2 B3 B4 15 b3 15 b3 01 72 00 00 04 00 00 00 00 02 00 02 40 41 42 43 44 45 46 47 5a 70 0f 88 e7 87".split(" ").reverse.mkString(""), 16),
          BigInt("fe 1c 1e f6 64 e6 01 ba 93 5f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 16 byte WG payload, tag mismatch
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-------- Ethernet header --------------> <-IPv4 header IHL=5 protocol=0x11->                         <--5555,5555,len0x172-> <-WG Type4> <receiver#> <-- Wireguard NONCE --> <- Single Beat,,
          BigInt("01 02 03 04 05 06 01 02 03 04 05 06 08 00 45 11 22 33 44 55 66 77 88 11 00 00 A1 A2 A3 A4 B1 B2 B3 B4 15 b3 15 b3 01 72 00 00 04 00 00 00 00 07 00 07 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89".split(" ").reverse.mkString(""), 16),
          BigInt("00 d6 f4 04 2a 8e 38 4e f4 bd f0 ed 2d 13 df 84 8e f7 0a c5 30 0b a0 45 59 ba 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 16 byte WG payload, tag match
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-------- Ethernet header --------------> <-IPv4 header IHL=5 protocol=0x11->                         <--5555,5555,len0x172-> <-WG Type4> <receiver#> <-- Wireguard NONCE --> <- Single Beat,,
          BigInt("01 02 03 04 05 06 01 02 03 04 05 06 08 00 45 11 22 33 44 55 66 77 88 11 00 00 A1 A2 A3 A4 B1 B2 B3 B4 15 b3 15 b3 01 72 00 00 04 00 00 00 00 03 00 03 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89".split(" ").reverse.mkString(""), 16),
          BigInt("46 d6 f4 04 2a 8e 38 4e f4 bd f0 ed 2d 13 df 84 8e f7 0a c5 30 0b a0 45 59 ba 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        Vector(
          //      <-------- Ethernet header --------------> <-IPv4 header IHL=5 protocol=0x11->                         <--5555,5555,len0x172-> <-WG Type4> <receiver#> <-- Wireguard NONCE --> <L  a  d  i  e  s
          BigInt("01 02 03 04 05 06 01 02 03 04 05 06 08 00 45 11 22 33 44 55 66 77 88 11 00 00 A1 A2 A3 A4 B1 B2 B3 B4 15 b3 15 b3 01 72 00 00 04 00 00 00 00 03 00 03 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89".split(" ").reverse.mkString(""), 16),
          BigInt("46 d6 f4 04 2a 8e 38 4e f4 bd 2f bc 73 30 b8 be 55 eb 2d 8d c1 8a aa 51 d6 6a 8e c1 f8 d3 61 9a 25 8d b0 ac 56 95 60 15 b7 b4 93 7e 9b 8e 6a a9 57 b3 dc 02 14 d8 03 d7 76 60 aa bc 91 30 92 97".split(" ").reverse.mkString(""), 16),
          BigInt("1d a8 f2 07 17 1c e7 84 36 08 16 2e 2e 75 9d 8e fc 25 d8 d0 93 69 90 af 63 c8 20 ba 87 e8 a9 55 b5 c8 27 4e f7 d1 0f 6f af d0 46 47 1b 14 57 76 ac a2 f7 cf 6a 61 d2 16 64 25 2f b1 f5 ba d2 ee".split(" ").reverse.mkString(""), 16),
          BigInt("98 e9 64 8b b1 7f 43 2d cc e4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        )
      )
      // meta-data about packet

      var packet_content_lengths = Vector(3 * 64 + 10, 64 + 10, 64 + 16 + 10, 64 + 16 + 10, 3 * 64 + 10)
      var packet_content_good    = Vector(true, true, false, true, true)

      // configurable
      val inter_packet_gap = 0
      val packet_num = 25

      // loop counters
      var packet_idx = 0
      var packet_content_idx = 0
      var expected_good = 0
      // iterate over all packets to be sent
      while (packet_idx < packet_num) {
        // choose one of the packet contents
        packet_content_idx = packet_idx % 5
        var remaining = packet_content_lengths(packet_content_idx)

        if (packet_content_good(packet_content_idx)) expected_good += 1

        var word_index = 0
        // iterate over frame content
        while (remaining > 0) {
          //printf("remaining = %d\n", remaining)
          val tkeep_len = if (remaining >= keepWidth) keepWidth else remaining;
          //printf("tkeep_len = %d\n", tkeep_len)
          valid0 = (Random.nextInt(8) > 2)
          valid0 &= !pause
          if (pause) pause ^= (Random.nextInt(16) >= 15)
          if (!pause) pause ^= (Random.nextInt(128) >= 127)

          assert(tkeep_len <= keepWidth)
          tkeep0 = 0
          data0 = 0
          if (valid0) {
            last0 = (remaining <= keepWidth)
            for (i <- 0 until tkeep_len) {
              tkeep0 = (tkeep0 << 1) | 1
            }
          }

          dut.io.sink.valid #= valid0
          dut.io.sink.payload.tdata #= packet_contents(packet_content_idx)(word_index)
          dut.io.sink.last #= last0
          dut.io.sink.last #= last0
          dut.io.sink.payload.tkeep #= tkeep0
          dut.io.sink.payload.tuser #= 0

          // Wait a rising edge on the clock
          dut.clockDomain.waitRisingEdge()

          if (dut.io.sink.ready.toBoolean & dut.io.sink.valid.toBoolean) {
            remaining -= tkeep_len
            word_index += 1
          }
        }
        // assert full packet is sent
        assert(remaining == 0)
        dut.io.sink.valid #= false
        printf("packet #%d sent (%s), %d good packets sent.\n", packet_idx,
          if (packet_content_good(packet_content_idx)) "good" else "bad ", expected_good)
        dut.clockDomain.waitRisingEdge(inter_packet_gap)
        packet_idx += 1
        //printf("packet #%d\n", packet_idx)
      } // while remaining_packets
      printf("Done sending %d packets, of which %d are good.\n", packet_idx, expected_good)

      //while (packets_rcvd < 4) {
      //    dut.clockDomain.waitRisingEdge(8)
      //}
      //printf("Received all expected packets\n")
      dut.clockDomain.waitRisingEdge(500)

      simSuccess()
    }
  }
}
