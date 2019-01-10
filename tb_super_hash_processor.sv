module tb_super_hash_processor();

logic           clk, reset_n, start;
logic   [  1:0] opcode;
logic   [ 31:0] message_addr, size, output_addr;
logic           done, mem_clk, mem_we;
logic   [ 15:0] mem_addr;
logic   [ 31:0] mem_write_data;
logic   [ 31:0] mem_read_data;

logic   [127:0] md5_hash; // results here
logic   [159:0] sha1_hash; // results here
logic   [255:0] sha256_hash; // results here

logic   [ 31:0] dpsram[0:16383]; // each row has 32 bits
logic   [ 31:0] dpsram_tb[0:16383]; // for result testing, testbench only

logic   [ 31:0] message_seed; // modify message_seed below

int             message_size = 505; // in bytes 
int             pad_length;

int             t, m;
int             outloop;
int             cycles;
int             total_cycles;
int             rounds;

logic           correct;

logic   [127:0] md5_digest;
logic   [159:0] sha1_digest;
logic   [255:0] sha256_digest;

logic   [ 31:0] h0;
logic   [ 31:0] h1;
logic   [ 31:0] h2;
logic   [ 31:0] h3;
logic   [ 31:0] h4;
logic   [ 31:0] h5;
logic   [ 31:0] h6;
logic   [ 31:0] h7;

logic   [ 31:0] a, b, c, d, e, f, g, h;
logic   [ 31:0] s1, s0;

logic   [ 31:0] w[0:79];

// instantiate your design
super_hash_processor super_hash_processor_inst (clk, reset_n, start, opcode, message_addr, size, output_addr, done,
    mem_clk, mem_we, mem_addr, mem_write_data, mem_read_data);

parameter string hnames[0:2] = {"MD5", "SHA1", "SHA256"};

// ---------------------------------------------------------------------------------------

// MD5 S constants
parameter byte S[0:63] = '{
    8'd7, 8'd12, 8'd17, 8'd22, 8'd7, 8'd12, 8'd17, 8'd22, 8'd7, 8'd12, 8'd17, 8'd22, 8'd7, 8'd12, 8'd17, 8'd22,
    8'd5, 8'd9,  8'd14, 8'd20, 8'd5, 8'd9,  8'd14, 8'd20, 8'd5, 8'd9,  8'd14, 8'd20, 8'd5, 8'd9,  8'd14, 8'd20,
    8'd4, 8'd11, 8'd16, 8'd23, 8'd4, 8'd11, 8'd16, 8'd23, 8'd4, 8'd11, 8'd16, 8'd23, 8'd4, 8'd11, 8'd16, 8'd23,
    8'd6, 8'd10, 8'd15, 8'd21, 8'd6, 8'd10, 8'd15, 8'd21, 8'd6, 8'd10, 8'd15, 8'd21, 8'd6, 8'd10, 8'd15, 8'd21
};

// MD5 K constants
parameter int md5_k[0:63] = '{
    32'hd76aa478, 32'he8c7b756, 32'h242070db, 32'hc1bdceee,
    32'hf57c0faf, 32'h4787c62a, 32'ha8304613, 32'hfd469501,
    32'h698098d8, 32'h8b44f7af, 32'hffff5bb1, 32'h895cd7be,
    32'h6b901122, 32'hfd987193, 32'ha679438e, 32'h49b40821,
    32'hf61e2562, 32'hc040b340, 32'h265e5a51, 32'he9b6c7aa,
    32'hd62f105d, 32'h02441453, 32'hd8a1e681, 32'he7d3fbc8,
    32'h21e1cde6, 32'hc33707d6, 32'hf4d50d87, 32'h455a14ed,
    32'ha9e3e905, 32'hfcefa3f8, 32'h676f02d9, 32'h8d2a4c8a,
    32'hfffa3942, 32'h8771f681, 32'h6d9d6122, 32'hfde5380c,
    32'ha4beea44, 32'h4bdecfa9, 32'hf6bb4b60, 32'hbebfbc70,
    32'h289b7ec6, 32'heaa127fa, 32'hd4ef3085, 32'h04881d05,
    32'hd9d4d039, 32'he6db99e5, 32'h1fa27cf8, 32'hc4ac5665,
    32'hf4292244, 32'h432aff97, 32'hab9423a7, 32'hfc93a039,
    32'h655b59c3, 32'h8f0ccc92, 32'hffeff47d, 32'h85845dd1,
    32'h6fa87e4f, 32'hfe2ce6e0, 32'ha3014314, 32'h4e0811a1,
    32'hf7537e82, 32'hbd3af235, 32'h2ad7d2bb, 32'heb86d391
};

// MD5 g
function logic[3:0] md5_g(input logic [7:0] t);
begin
   if (t <= 15)
       md5_g = t;
   else if (t <= 31)
       md5_g = (5*t + 1) % 16;
   else if (t <= 47)
       md5_g = (3*t + 5) % 16;
   else
       md5_g = (7*t) % 16;
end
endfunction

// MD5 f
function logic[31:0] md5_f(input logic [7:0] t);
begin
    if (t <= 15)
        md5_f = (b & c) | ((~b) & d);
    else if (t <= 31)
        md5_f = (d & b) | ((~d) & c);
    else if (t <= 47)
        md5_f = b ^ c ^ d;
    else
        md5_f = c ^ (b | (~d));
end
endfunction

// MD5 hash round
function logic[127:0] md5_op(input logic [31:0] a, b, c, d, w,
                             input logic [7:0] t);
    logic [31:0] t1, t2; // internal signals
begin
    t1 = a + md5_f(t) + md5_k[t] + w;
    t2 = b + ((t1 << S[t])|(t1 >> (32-S[t])));
    md5_op = {d, t2, b, c};
end
endfunction

// ---------------------------------------------------------------------------------------

// SHA1 f
function logic [31:0] sha1_f(input logic [7:0] t);
begin
   if (t <= 19)
       sha1_f = (b & c) | ((~b) & d);
   else if (t <= 39)
       sha1_f = b ^ c ^ d;
   else if (t <= 59)
       sha1_f = (b & c) | (b & d) | (c & d);
   else
       sha1_f = b ^ c ^ d;
end
endfunction

// SHA1 k
function logic [31:0] sha1_k(input logic [7:0] t);
begin
   if (t <= 19)
       sha1_k = 32'h5a827999;
   else if (t <= 39)
       sha1_k = 32'h6ed9eba1;
   else if (t <= 59)
       sha1_k = 32'h8f1bbcdc;
   else
       sha1_k = 32'hca62c1d6;
end
endfunction

// SHA1 hash round
function logic [159:0] sha1_op(input logic [31:0] a, b, c, d, e, w,
                               input logic [7:0] t);
   logic [31:0] temp, tc; // internal signals
begin
   temp = ((a << 5)|(a >> 27)) + sha1_f(t) + e + sha1_k(t) + w;
   tc = ((b << 30)|(b >> 2));
   sha1_op = {temp, a, tc, c, d};
end
endfunction

// ---------------------------------------------------------------------------------------

// SHA256 K constants
parameter int sha256_k[0:63] = '{
   32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
   32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
   32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
   32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
   32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
   32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
   32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
   32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + sha256_k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// ---------------------------------------------------------------------------------------

// left rotation
function logic [31:0] leftrotate(input logic [31:0] x);
begin
    leftrotate = (x << 1) | (x >> 31);
end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    rightrotate = (x >> r) | (x << (32-r));
end
endfunction

// convert from little-endian to big-endian
function logic [31:0] changeEndian(input logic [31:0] value);
    changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction

// ---------------------------------------------------------------------------------------

// clock generator
always begin
    #10;
    clk = 1'b1;
    #10
    clk = 1'b0;
end

// main testbench
initial
begin
  total_cycles = 0;

  for (opcode = 0; opcode < 3; opcode = opcode + 1) begin
    // RESET HASH CO-PROCESSOR

    @(posedge clk) reset_n = 0;
    for (m = 0; m < 2; m = m + 1) @(posedge clk);
    reset_n = 1;
    for (m = 0; m < 2; m = m + 1) @(posedge clk);

    // SET MESSAGE LOCATION

    size = message_size;

    case (opcode)
    2'b00: begin // md5
        message_addr = 32'd1000;
        message_seed = 32'h01234567; 
      end
    2'b01: begin // sha1
        message_addr = 32'd2000;
        message_seed = 32'h34567012; 
      end
    default: begin // sha256
        message_addr = 32'd3000;
        message_seed = 32'h45670123; 
      end
    endcase

    output_addr = message_addr + ((message_size-1))/4 + 1;

    // CREATE AND DISPLAY MESSAGETEXT

    $display("-----------\n");
    $display("Messagetext\n");
    $display("-----------\n");

    dpsram[message_addr+0] = message_seed;
    dpsram_tb[0] = changeEndian(message_seed); // change Endian // for testbench only

    $display("%x\n", dpsram[message_addr]);

    for (m = 1; m < (message_size-1)/4+1; m = m + 1) begin // data generation
        dpsram[message_addr+m] = (dpsram[message_addr+m-1]<<1)|(dpsram[message_addr+m-1]>>31);
        dpsram_tb[m] = changeEndian(dpsram[message_addr+m]); // change Endian
        $display("%x\n", dpsram[message_addr+m]);
    end

    // START PROCESSOR

    start = 1'b1;
    for (m = 0; m < 2; m = m + 1) @(posedge clk);
    start = 1'b0;

    // PERFORM PADDING OF MESSAGE

    // calculate total number of bytes after padding (before appending total length)
    if ((message_size + 1) % 64 <= 56 && (message_size + 1) % 64 > 0)
        pad_length = (message_size/64)*64 + 56;
    else
        pad_length = (message_size/64+1)*64 + 56;

    case (message_size % 4) // pad bit 1
    0: dpsram_tb[message_size/4] = 32'h80000000;
    1: dpsram_tb[message_size/4] = dpsram_tb[message_size/4] & 32'h FF000000 | 32'h 00800000;
    2: dpsram_tb[message_size/4] = dpsram_tb[message_size/4] & 32'h FFFF0000 | 32'h 00008000;
    3: dpsram_tb[message_size/4] = dpsram_tb[message_size/4] & 32'h FFFFFF00 | 32'h 00000080;
    endcase

    for (m = message_size/4+1; m < pad_length/4; m = m + 1) begin
        dpsram_tb[m] = 32'h00000000;
    end

    dpsram_tb[pad_length/4] = message_size >> 29; // append length of message in bits (before pre-processing)
    dpsram_tb[pad_length/4+1] = message_size * 8;
    pad_length = pad_length + 8; // final length after pre-processing

    outloop = pad_length/64; // break message into 512-bit chunks (64 bytes)

    // COMPUTE NUMBER OF ROUNDS

    if (opcode == 2'b01) // sha1
        rounds = 80;
    else // md5 or sha256
        rounds = 64;

    // SET INITIAL HASH

    case (opcode)
    2'b00: begin // md5
        h0 = 32'h67452301;
        h1 = 32'hEFCDAB89;
        h2 = 32'h98BADCFE;
        h3 = 32'h10325476;
        h4 = 32'h00000000;
        h5 = 32'h00000000;
        h6 = 32'h00000000;
        h7 = 32'h00000000;
      end
    2'b01: begin // sha1
        h0 = 32'h67452301;
        h1 = 32'hEFCDAB89;
        h2 = 32'h98BADCFE;
        h3 = 32'h10325476;
        h4 = 32'hC3D2E1F0;
        h5 = 32'h00000000;
        h6 = 32'h00000000;
        h7 = 32'h00000000;
      end
    default: begin // sha256
        h0 = 32'h6a09e667;
        h1 = 32'hbb67ae85;
        h2 = 32'h3c6ef372;
        h3 = 32'ha54ff53a;
        h4 = 32'h510e527f;
        h5 = 32'h9b05688c;
        h6 = 32'h1f83d9ab;
        h7 = 32'h5be0cd19;
      end
    endcase

    // COMPUTE SHA256 HASH

    for (m = 0; m < outloop; m = m + 1) begin
        // W ARRAY EXPANSION

        for (t = 0; t < rounds; t = t + 1) begin
            if (t < 16) begin
                w[t] = dpsram_tb[t+m*16];
            end else begin
              case (opcode)
              2'b00: begin // md5
                w[t] = w[md5_g(t)];
              end
              2'b01: begin // sha1
                w[t] = leftrotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]);
              end
              default: begin // sha256
                s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
                s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
                w[t] = w[t-16] + s0 + w[t-7] + s1;
              end
              endcase
            end
        end

        // INITIAL HASH AT ROUND K

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        // HASH ROUNDS

        for (t = 0; t < rounds; t = t + 1) begin
            case (opcode)
            2'b00: 
                {a, b, c, d} = md5_op(a, b, c, d, w[t], t);
            2'b01: 
                {a, b, c, d, e} = sha1_op(a, b, c, d, e, w[t], t);
            default:
                {a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, w[t], t);
            endcase
        end

        // FINAL HASH

        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    end

    md5_digest = {h0, h1, h2, h3};
    sha1_digest = {h0, h1, h2, h3, h4};
    sha256_digest = {h0, h1, h2, h3, h4, h5, h6, h7};

    // WAIT UNTIL ENTIRE FRAME IS HASHED, THEN DISPLAY HASH RESULT

    wait (done == 1);

    // DISPLAY HASH RESULT

    $display("-----------------------\n");
    $display("correct %s hash result is:\n", hnames[opcode]);
    $display("-----------------------\n");
    case (opcode)
    2'b00: // md5
        $display("%x\n", md5_digest);
    2'b01: // sha1
        $display("%x\n", sha1_digest);
    default: // sha256
        $display("%x\n", sha256_digest);
    endcase

    md5_hash = {
        dpsram[output_addr],
        dpsram[output_addr+1],
        dpsram[output_addr+2],
        dpsram[output_addr+3]
    };

    sha1_hash = {
        dpsram[output_addr],
        dpsram[output_addr+1],
        dpsram[output_addr+2],
        dpsram[output_addr+3],
        dpsram[output_addr+4]
    };

    sha256_hash = {
        dpsram[output_addr],
        dpsram[output_addr+1],
        dpsram[output_addr+2],
        dpsram[output_addr+3],
        dpsram[output_addr+4],
        dpsram[output_addr+5],
        dpsram[output_addr+6],
        dpsram[output_addr+7]
    };

    $display("-----------------------\n");
    $display("Your %s result is:        \n", hnames[opcode]);
    $display("-----------------------\n");
    case (opcode)
    2'b00: // md5
        $display("%x\n", md5_hash);
    2'b01: // sha1
        $display("%x\n", sha1_hash);
    default: // sha256
        $display("%x\n", sha256_hash);
    endcase

    $display("***************************\n");

    correct = 1'b0;
    case (opcode)
    2'b00: // md5
        correct = (md5_digest == md5_hash);
    2'b01: // sha1
        correct = (sha1_digest == sha1_hash);
    default: // sha256
        correct = (sha256_digest == sha256_hash);
    endcase

    if (correct) begin
        $display("Congratulations! You have the correct %s hash result!\n", hnames[opcode]);
        $display("Total number of %s cycles: %d\n\n", hnames[opcode], cycles);
    end else begin
        $display("Error! The %s hash result is wrong!\n", hnames[opcode]);
    end

    total_cycles = total_cycles + cycles;

    $display("***************************\n");
  end
  $display("FINAL TOTAL NUMBER OF CYCLES: %d\n\n", total_cycles);
  $display("***************************\n");

  $stop;
end

// memory model
always @(posedge mem_clk)
begin
    if (mem_we) // write
        dpsram[mem_addr] = mem_write_data;
    else // read
        mem_read_data = dpsram[mem_addr];
end

// track # of cycles
always @(posedge clk)
begin
    if (!reset_n)
        cycles = 0;
    else
        cycles = cycles + 1;
end

endmodule