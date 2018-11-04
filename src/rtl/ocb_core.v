//======================================================================
//
// ocb_core.v
// ----------
// OCB authenticated encryption (AE) mode for AES. This implementation
// corresponds to OCB3 as specified in RFC abcd.
// as used in RFC 4493.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2018, Assured AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module ocb_core(
                input wire            clk,
                input wire            reset_n,

                input wire [255 : 0]  key,
                input wire            keylen,

                input wire            encdec,
                input wire [7 : 0]    final_size,

                input wire            init,
                input wire            next,
                input wire            finalize,

                input wire [127 : 0]  block,

                output wire [127 : 0] result,
                output wire [127 : 0] tag,
                output wire           ready,
                output wire           valid
                );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE        = 0;
  localparam CTRL_INIT_CORE   = 1;
  localparam CTRL_NEXT_BLOCK  = 2;
  localparam CTRL_FINAL_BLOCK = 3;


  localparam AES_BLOCK_SIZE = 128;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [127 : 0] result_reg;
  reg [127 : 0] result_new;
  reg           result_we;
  reg           reset_result_reg;
  reg           update_result_reg;

  reg           valid_reg;
  reg           valid_new;
  reg           valid_we;
  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [3 : 0]   ocb_ctrl_reg;
  reg [3 : 0]   ocb_ctrl_new;
  reg           ocb_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            aes_init;
  reg            aes_next;
  wire           aes_ready;
  reg  [127 : 0] aes_block;
  wire [127 : 0] aes_result;
  wire           aes_valid;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign result = result_reg;
  assign ready  = ready_reg;
  assign valid  = valid_reg;


  //----------------------------------------------------------------
  // AES core instantiation.
  //----------------------------------------------------------------
  aes_core aes_inst(
                    .clk(clk),
                    .reset_n(reset_n),

                    .encdec(encdec),
                    .init(aes_init),
                    .next(aes_next),
                    .ready(aes_ready),

                    .key(key),
                    .keylen(keylen),

                    .block(aes_block),
                    .result(aes_result),
                    .result_valid(aes_valid)
                   );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin : reg_update
      if (!reset_n)
        begin
          result_reg     <= 128'h0;
          valid_reg      <= 1'h0;
          ready_reg      <= 1'h1;
          ocb_ctrl_reg  <= CTRL_IDLE;
        end
      else
        begin
          if (result_we)
            result_reg <= result_new;

          if (ready_we)
            ready_reg <= ready_new;

          if (valid_we)
            valid_reg <= valid_new;

          if (ocb_ctrl_we)
            ocb_ctrl_reg <= ocb_ctrl_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // ocb_datapath
  //----------------------------------------------------------------
  always @*
    begin : ocb_datapath
      reg [127 : 0] offset;

      result_new = 128'h0;
      result_we  = 0;

      // Handle result reg updates and clear
      if (reset_result_reg)
        result_we  = 1'h1;

      if (update_result_reg)
        begin
          result_new = aes_result;
          result_we  = 1'h1;
        end
    end


  //----------------------------------------------------------------
  // ocb_ctrl
  //----------------------------------------------------------------
  always @*
    begin : ocb_ctrl
      aes_init          = 1'h0;
      aes_next          = 1'h0;
      reset_result_reg  = 1'h0;
      update_result_reg = 1'h0;
      ready_new         = 1'h0;
      ready_we          = 1'h0;
      valid_new         = 1'h0;
      valid_we          = 1'h0;
      ocb_ctrl_new     = CTRL_IDLE;
      ocb_ctrl_we      = 1'h0;

      case (ocb_ctrl_reg)
        CTRL_IDLE:
          begin
            if (init)
              begin
                ready_new        = 1'h0;
                ready_we         = 1'h1;
                valid_new        = 1'h0;
                valid_we         = 1'h1;
                aes_init         = 1'h1;
                reset_result_reg = 1'h1;
                ocb_ctrl_new    = CTRL_INIT_CORE;
                ocb_ctrl_we     = 1'h1;
              end

            if (next)
              begin
                ready_new     = 1'h0;
                ready_we      = 1'h1;
                aes_next      = 1'h1;
                ocb_ctrl_new  = CTRL_NEXT_BLOCK;
                ocb_ctrl_we   = 1'h1;
              end

            if (finalize)
              begin
                ready_new     = 1'h0;
                ready_we      = 1'h1;
                aes_next      = 1'h1;
                ocb_ctrl_new  = CTRL_FINAL_BLOCK;
                ocb_ctrl_we   = 1'h1;
              end
          end

        CTRL_INIT_CORE:
          begin
            if (aes_ready)
              begin
                ocb_ctrl_new = CTRL_IDLE;
                ocb_ctrl_we  = 1'h1;
              end
          end

        CTRL_NEXT_BLOCK:
          begin
            if (aes_ready)
              begin
                ocb_ctrl_new = CTRL_IDLE;
                ocb_ctrl_we  = 1'h1;
              end
          end

        CTRL_FINAL_BLOCK:
          begin
            if (aes_ready)
              begin
                ocb_ctrl_new = CTRL_IDLE;
                ocb_ctrl_we  = 1'h1;
              end
          end

        default:
          begin
          end
      endcase // case (ocb_ctrl_reg)
    end

endmodule // ocb_core

//======================================================================
// EOF ocb_core.v
//======================================================================
