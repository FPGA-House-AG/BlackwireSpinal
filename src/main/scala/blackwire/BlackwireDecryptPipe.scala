package blackwire

import spinal.core._
import spinal.lib._

import spinal.lib.bus.misc._
import spinal.lib.bus.amba4.axi._

import scala.math._

import corundum._

// companion object
object BlackwireDecryptPipe {
  val busconfig = Axi4Config(15, 32, 2, useLock = false, useQos = false, useRegion = false)
  def main(args: Array[String]) : Unit = {
    val vhdlReport = Config.spinal.generateVhdl(new BlackwireDecryptPipe(busconfig))
    val verilogReport = Config.spinal.generateVerilog(new BlackwireDecryptPipe(busconfig))
    //vhdlReport.mergeRTLSource("merge")
  }
}

case class BlackwireDecryptPipe(busCfg : Axi4Config, instanceNr : Int = 0, has_busctrl : Boolean = true, include_chacha : Boolean = true) extends Component {
  final val corundumDataWidth = 512
  final val cryptoDataWidth = 128
  final val maxPacketLength = 1534

  val io = new Bundle {
    // I/O is the Corundum Frame AXIS tdata/tkeep/tuser format payload
    val sink = slave Stream Fragment(CorundumFrame(corundumDataWidth))
    val source = master Stream Fragment(CorundumFrame(corundumDataWidth))
    val rxkey_sink = slave Stream(Bits(256 bits))
  }

  val crypto_instash  = CorundumFrameFlowStash(corundumDataWidth, fifoSize = 32, 24)

  crypto_instash.io.sink << io.sink

  // vvv is stash output but as AXIS TDATA and packet length in bytes as a sideband signal
  val vvv = Stream(Fragment(Bits(corundumDataWidth bits)))
  val frr = Fragment(Bits(corundumDataWidth bits))
  frr.last := crypto_instash.io.source.payload.last
  frr.fragment := crypto_instash.io.source.payload.fragment.tdata
  vvv <-< crypto_instash.io.source.translateWith(frr)
  val vvv_length = RegNextWhen(crypto_instash.io.length, crypto_instash.io.source.firstFire)

  // z is the Type 4 packet in 128 bits
  val z = Stream(Fragment(Bits(cryptoDataWidth bits)))
  val downsizer = AxisDownSizer(corundumDataWidth, cryptoDataWidth)
  downsizer.io.sink << vvv
  downsizer.io.sink_length := vvv_length
  z <-< downsizer.io.source
  val z_length = RegNextWhen(downsizer.io.source_length, z.ready)

  val k = Stream(Fragment(Bits(cryptoDataWidth bits)))
  k << z
  val k_length = z_length

  // s is the decrypted Type 4 payload but with the length determined from the IP header
  val s = Stream(Fragment(Bits(cryptoDataWidth bits)))
  val s_length = UInt(12 bits)
  val s_drop = Bool()

  // keep track of number of 128-bit words in the very deep ChaCha pipeline
  val inflight_count = CounterUpDown(512)
  // count payload words, not including the WireGuard Type 4 header nor Poly1305 tag, both one word
  when (RegNext(downsizer.io.source.fire && !downsizer.io.source.isFirst && !downsizer.io.source.isLast)) {
    inflight_count.increment()
  }
  
  // forward declaration of feedback signal
  val output_stash_available = UInt(log2Up(128 + 1) bits)
  // calculate the unreserved FIFO words (i.e. available in the FIFO but not inflight towards it)
  val output_stash_unreserved = RegNext(RegNext(output_stash_available * (512/128)) - RegNext(inflight_count.value))
  val output_stash_too_full = RegNext(output_stash_unreserved < 64/*@TODO tune down to 32 maybe but with formal verification against overflowing the FIFO*/)
  // only halt after a packet but only if too full, always go whenever not too full (last assignment wins)
  val halt_input_to_chacha = RegInit(False).setWhen(k.lastFire).clearWhen(!output_stash_too_full)

  val with_chacha = (include_chacha) generate new Area {
    // round up to next 16 bytes (should we always do this? -- Ethernet MTU?)
    //val padded16_length_out = RegNextWhen(((k_length + 15) >> 4) << 4, k.isFirst)
    // remove 128 bits Wireguard Type 4 header and 128 bits tag from output length
    //val plaintext_length_out = padded16_length_out - 128/8 - 128/8

    val plaintext_length_out = RegNextWhen((((k_length + 15/*round up*/) >> 4/*pad*/) - 1/*header*/ - 1/*tag*/) << 4/*pad*/, k.isFirst)

    // l is k but with length
    val l = Stream(Fragment(Bits(cryptoDataWidth bits)))
    l <-< k.haltWhen(halt_input_to_chacha)
  
    // write plaintext length into bytes 1-3
    when (l.isFirst) {
      l.payload.fragment(8, 24 bits).assignFromBits(plaintext_length_out.resize(24).asBits.subdivideIn(8 bits).reverse.asBits)
    }

    val m = Stream(Fragment(Bits(cryptoDataWidth bits)))
    m << l.s2mPipe().m2sPipe()

    val rxkey = io.rxkey_sink.s2mPipe().m2sPipe()

    // p is the decrypted Type 4 payload
    val p = Stream(Fragment(Bits(cryptoDataWidth bits)))
    val decrypt = ChaCha20Poly1305DecryptSpinal()
    decrypt.io.sink << m
    decrypt.io.key := rxkey.payload
    p << decrypt.io.source.s2mPipe().m2sPipe()
    // pop key from RX key FIFO 
    rxkey.ready := m.firstFire

    // from the first word, extract the IPv4 Total Length field to determine packet length
    //when (p.isFirst) {
    //  s_length.assignFromBits(p.payload.fragment(16, 16 bits).resize(12))
    //}
    s_length := RegNextWhen(U(p.payload.fragment(16, 16 bits).resize(12)), p.firstFire)
    s <-< p

    // @NOTE tag_valid is unknown before TLAST beats, so AND it with TLAST
    // to prevent inserting an unknown drop signal on non-last beats to the output
    s_drop := RegNextWhen(p.last & !decrypt.io.tag_valid, p.ready).init(False)
    if (instanceNr == 0) {
      decrypt.io.addAttribute("mark_debug")
    }
  }
  val without_chacha = (!include_chacha) generate new Area { 
    s << k.haltWhen(halt_input_to_chacha)
    s_length := k_length
    s_drop := False
  }

  // u is the decrypted Type 4 payload but in 512 bits
  val u = Stream(Fragment(Bits(corundumDataWidth bits)))
  val upsizer = AxisUpSizer(cryptoDataWidth, corundumDataWidth)
  // @NOTE consider pipeline stage
  upsizer.io.sink << s
  upsizer.io.sink_length := s_length
  upsizer.io.sink_drop := s_drop
  u << upsizer.io.source
  val u_length = upsizer.io.source_length
  val u_drop = upsizer.io.source_drop

  when (RegNext(upsizer.io.sink.fire)) {
    inflight_count.decrement()
  }


  printf("Upsizer Latency = %d clock cycles.\n", LatencyAnalysis(s.valid, u.valid))

  // c is the decrypted Type 4 payload but in 512 bits in Corundum format
  // c does not experience back pressure during a packet out
  val c = Stream Fragment(CorundumFrame(corundumDataWidth))
  val corundum = AxisToCorundumFrame(corundumDataWidth)
  // @NOTE consider pipeline stage
  corundum.io.sink << u
  corundum.io.sink_length := u_length
  corundum.io.sink_drop := u_drop
  c << corundum.io.source
  
  // r is the decrypted Type 4 payload but in 512 bits in Corundum format
  // r can receive back pressure from Corundum
  val r = Stream Fragment(CorundumFrame(corundumDataWidth))

  // should be room for 1534 + latency of ChaCha20 to FlowStash
  // Flow goes ready after packet last, and room for 26*64=1664 bytes
  val crypto_outstash = CorundumFrameFlowStash(corundumDataWidth, fifoSize = 128, 24)
  crypto_outstash.io.sink << c
  r << crypto_outstash.io.source

  // let synthesis optimize out the ready signal; i.e. make this a flow to increase clock rate
  when (True) {
    c.ready := True
  }

  output_stash_available := crypto_outstash.io.availability

  io.source << r

  // Execute the function renameAxiIO after the creation of the component
  addPrePopTask(() => CorundumFrame.renameAxiIO(io))
}

import spinal.sim._
import spinal.core.sim._
import scala.util.Random

object BlackwireDecryptPipeSim {
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

    .compile {
      val dut = new BlackwireDecryptPipe(BlackwireDecryptPipe.busconfig, include_chacha = include_chacha)
      dut.with_chacha.decrypt.io.sink.ready.simPublic()
      dut.with_chacha.decrypt.io.sink.valid.simPublic()
      dut.with_chacha.decrypt.io.sink.last.simPublic()
      dut.with_chacha.decrypt.io.source.ready.simPublic()
      dut.with_chacha.decrypt.io.source.valid.simPublic()
      dut.with_chacha.decrypt.io.source.last.simPublic()
      dut.with_chacha.decrypt.io.tag_valid.simPublic()
      dut.with_chacha.decrypt.io.tag_pulse.simPublic()
      dut
    }
    //.addSimulatorFlag("-Wno-TIMESCALEMOD")
    // include_chacha = true requires GHDL or XSim
    .doSim { dut =>

      //SimTimeout(30000)

      dut.io.sink.valid #= false

      //Fork a process to generate the reset and the clock on the dut
      dut.clockDomain.forkStimulus(period = 10)

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

      dut.io.rxkey_sink.payload #= BigInt("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f".split(" ")/*.reverse*/.mkString(""), 16)
      dut.io.rxkey_sink.valid #= true

      dut.io.source.ready #= true //false

      dut.clockDomain.waitSampling()

      // monitor output (source) of DUT
      var good_packets = 0
      var packets_rcvd = 0
      var tags_rcvd = 0
      val monitorThread = fork {
        while (true) {
          if (dut.with_chacha.decrypt.io.source.valid.toBoolean & dut.with_chacha.decrypt.io.source.last.toBoolean & dut.with_chacha.decrypt.io.source.ready.toBoolean) {
            packets_rcvd += 1
            printf("packets received #%d\n", packets_rcvd)
          }
          if (include_chacha) {
            if (dut.with_chacha.decrypt.io.tag_pulse.toBoolean)
            {
              tags_rcvd += 1
              printf("dut.with_chacha.decrypt.io.tag_valid = %b\n", dut.with_chacha.decrypt.io.tag_valid.toBoolean)
              if (dut.with_chacha.decrypt.io.tag_valid.toBoolean == true) {
                good_packets += 1
                printf("good_packets #%d\n", good_packets)
              }
            }
          }
          dut.clockDomain.waitSampling()
        }
      }

      val backpressureThread = fork {
        while (true) {
          dut.io.source.ready #= (Random.nextInt(100) > 95)
          dut.clockDomain.waitSampling()
        }
      }

// "0102030405060102030405060102" Ethernet
// "xxxx11887766554433221145" IPv4, IHL=5, protocol=0x11 (UDP)
// "0000FF0000000000000000FF"
// "CCCCLLLLb315SSSS", DDDD=port 5555 (0x15b3)
// "00000000FFFF0000"

      var packet_idx = 0
      val inter_packet_gap = 0

      val packet_contents = Vector(
        // RFC7539 2.8.2. Example and Test Vector for AEAD_CHACHA20_POLY1305
        // but with zero-length AAD, and Wireguard 64-bit nonce
        Vector(
          //      <-WG Type4> <receiver#> <-- Wireguard NONCE --> <L  a  d  i  e  s
          BigInt("04 00 00 80 00 01 00 01 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89 46 d6 f4 04 2a 8e 38 4e f4 bd 2f bc 73 30 b8 be 55 eb 2d 8d c1 8a aa 51 d6 6a 8e c1 f8 d3 61 9a 25 8d b0 ac 56 95 60 15 b7 b4".split(" ").reverse.mkString(""), 16),
          BigInt("93 7e 9b 8e 6a a9 57 b3 dc 02 14 d8 03 d7 76 60 aa bc 91 30 92 97 1d a8 f2 07 17 1c e7 84 36 08 16 2e 2e 75 9d 8e fc 25 d8 d0 93 69 90 af 63 c8 20 ba 87 e8 a9 55 b5 c8 27 4e f7 d1 0f 6f af d0".split(" ").reverse.mkString(""), 16),
          BigInt("46 47 1b 14 57 76 ac a2 f7 cf 6a 61 d2 16 64 25 2f b1 f5 ba d2 ee 98 e9 64 8b b1 7f 43 2d cc e4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 0 byte WG payload, tag match
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-WG Type4> <receiver#> <-- Wireguard NONCE --> <- Poly 1305 Tag ----------------------------->
          BigInt("04 00 00 20 00 02 00 02 40 41 42 43 44 45 46 47 5a 70 0f 88 e7 87 fe 1c 1e f6 64 e6 01 ba 93 5f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 16 byte WG payload, tag mismatch
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-WG Type4> <receiver#> <-- Wireguard NONCE -->                                                 <- Poly 1305 Tag ----------------------------->
          BigInt("04 00 00 20 00 03 00 03 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89 00 d6 f4 04 2a 8e 38 4e f4 bd f0 ed 2d 13 df 84 8e f7 0a c5 30 0b a0 45 59 ba 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        // 16 byte WG payload, tag match
        Vector( // @TODO UDP length does not match - is ignored 
          //      <-WG Type4> <receiver#> <-- Wireguard NONCE -->                                                 <- Poly 1305 Tag ----------------------------->
          BigInt("04 00 00 20 00 04 00 04 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89 46 d6 f4 04 2a 8e 38 4e f4 bd f0 ed 2d 13 df 84 8e f7 0a c5 30 0b a0 45 59 ba 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        ),
        Vector(
          //      <-WG Type4> <receiver#> <-- Wireguard NONCE --> <L  a  d  i  e  s
          BigInt("04 00 00 80 00 05 00 05 40 41 42 43 44 45 46 47 a4 79 cb 54 62 89 46 d6 f4 04 2a 8e 38 4e f4 bd 2f bc 73 30 b8 be 55 eb 2d 8d c1 8a aa 51 d6 6a 8e c1 f8 d3 61 9a 25 8d b0 ac 56 95 60 15 b7 b4".split(" ").reverse.mkString(""), 16),
          BigInt("93 7e 9b 8e 6a a9 57 b3 dc 02 14 d8 03 d7 76 60 aa bc 91 30 92 97 1d a8 f2 07 17 1c e7 84 36 08 16 2e 2e 75 9d 8e fc 25 d8 d0 93 69 90 af 63 c8 20 ba 87 e8 a9 55 b5 c8 27 4e f7 d1 0f 6f af d0".split(" ").reverse.mkString(""), 16),
          BigInt("46 47 1b 14 57 76 ac a2 f7 cf 6a 61 d2 16 64 25 2f b1 f5 ba d2 ee 98 e9 64 8b b1 7f 43 2d cc e4 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" ").reverse.mkString(""), 16)
        )
      )
      val packet_content_lengths = Vector(64 + 64 + 32, 16+16, 16 + 16 + 16, 16 + 16 + 16, 64 + 64 + 32)
      val packet_content_good    = Vector(true, true, false, true, true)

      val packet_num = 25
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

      while (tags_rcvd < packet_num) {
          dut.clockDomain.waitRisingEdge(8)
          printf("Received %d of %d expected packets.\n", tags_rcvd, packet_num)
      }
      dut.clockDomain.waitRisingEdge(64)
      dut.clockDomain.waitRisingEdge(8)
      printf("Expected %d good packets and saw %d good packets.\n", expected_good, good_packets)
      assert(good_packets == expected_good)

      simSuccess()
    }
  }
}
