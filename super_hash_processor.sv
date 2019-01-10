module super_hash_processor(input logic clk, reset_n, start,
input logic [1:0] opcode,
input logic [31:0] message_addr, size, output_addr,
output logic done, mem_clk, mem_we,
output logic [15:0] mem_addr,
output logic [31:0] mem_write_data,
input logic [31:0] mem_read_data);

enum logic [3:0] {SETUP=4'b0000, IDLE=4'b0001, READ=4'b0010, PAD=4'b0011, HASH=4'b0100, POST_HASH=4'b0101, OUTPUT=4'b0110, DONE=4'b1110} state;
logic [31:0] counter;
//logic [31:0] temp_address; //uncomment if doing more than one hash
logic [31:0] current_block;
logic [31:0] limit;
logic [31:0] registers;
logic [31:0] w[0:15];
logic [31:0] a, b, c, d, e, f, fsha1, g, h, k, temp;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a1, b1, c1, d1, e1;

assign mem_clk = clk;

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
	begin
		 rightrotate = (x >> r) | (x << (32-r));
	end
endfunction

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
	//debug
	/*
	$display("w == %x\n",w);
	$display("--------------------------\n");
	*/
    t1 = a + md5_f(t) + md5_k[t] + w;
    t2 = b + ((t1 << S[t])|(t1 >> (32-S[t])));
    md5_op = {d, t2, b, c};
end
endfunction

//sha1 hash
 function logic [159:0] hash_op(input logic [31:0] a, b, c, d, e, w, input logic [31:0] t);
	if(t<=19)begin
		k = 32'h5A827999;
		fsha1 = (b & c) | ( (~b) & d);
	end else 	
	
	if(t <=39)begin
		k = 32'h6ED9EBA1;
		fsha1 = b ^ c ^ d;
	end else
	
	if(t<=59)begin
		k = 32'h8F1BBCDC;
		fsha1 = (b & c) | (b & d) | (c & d);
	end else 
	
	begin
		k = 32'hCA62C1D6;	
		fsha1 = b ^ c ^ d;
	end
	//debug
	/*	
	$display("a == %x\n",a);
	$display("b == %x\n",b);
	$display("c == %x\n",c);
	$display("d == %x\n",d);
	$display("e == %x\n",e);
	$display("f == %x\n",f);	
	$display("w == %x\n",w);
	*/	
	temp = {a[26:0],a[31:27]} + fsha1 + e + k + w;
	//debug
	/*
	$display("temp == %x\n",temp);	
	$display("-------------------------------");	
	*/
	e = d;
	d = c;
	c = {b[1:0],b[31:2]};
	b = a;
	a = temp;
	hash_op = {a, b, c, d, e};
endfunction

// convert from little-endian to big-endian
function logic [31:0] changeEndian(input logic [31:0] value);
	changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction
  
//appending pading "1"  
function logic [31:0] magic(input logic [31:0] value);
begin
	if(size%4 == 1)begin
		magic = ((value & 32'hFF000000) | 32'h00800000);
	end
	if(size%4 == 2) begin
		magic = ((value & 32'hFFFF0000) | 32'h00008000);
	end
	if(size%4 == 3) begin
		magic = ((value & 32'hFFFFFF00) | 32'h00000080);
	end
end
endfunction  
  
//determine number of blocks
function logic [31:0] determine_num_blocks(input logic [31:0] size);
	determine_num_blocks = ((((size)+8)/64)+1);
endfunction


  always_ff @(posedge clk, negedge reset_n)
  begin
    if (!reset_n) begin
      state <= SETUP;
    end else
      casex (state)
			SETUP: begin
			w[0]<=0; //set block to zeros to avoid padding 0s
			w[1]<=0;
			w[2]<=0;
			w[3]<=0; 
			w[4]<=0; 
			w[5]<=0;
			w[6]<=0;
			w[7]<=0;
			w[8]<=0;
			w[9]<=0;
			w[10]<=0;
			w[11]<=0;
			w[12]<=0;
			w[13]<=0;
			w[14]<=0;
			w[15]<=0;
			if(opcode == 2'b01 || opcode == 2'b00) begin // set constants depending on operation
				h0 <= 32'h67452301;
				h1 <= 32'hEFCDAB89;
				h2 <= 32'h98BADCFE;
				h3 <= 32'h10325476;
				h4 <= 32'hC3D2E1F0;
			end
			if(opcode == 2'b10) begin
				h0 <= 32'h6a09e667;
				h1 <= 32'hbb67ae85;
				h2 <= 32'h3c6ef372;
				h3 <= 32'ha54ff53a;
				h4 <= 32'h510e527f;
				h5 <= 32'h9b05688c;
				h6 <= 32'h1f83d9ab;
				h7 <= 32'h5be0cd19;
			end
			//temp_addr <= output_addr; //uncomment if doing more than one hash 
			state <= IDLE;
			done <= 0;
		end	
			
      IDLE: // start
          if(start) begin // READ first word
				current_block<=determine_num_blocks(size);
				registers <= size/4 + size[0];
				if(size >= 64) begin //if message is more than 512 bits
					limit <= 16;
				end
				if (size < 64) begin //if message is less than 512 bits
					limit <= size/4 + size[0];
				end					
            counter <= 0;
            state <= READ;	
				mem_addr <= message_addr - 1; //account for reading dealys		
          end
		
		READ: begin
			mem_addr <= mem_addr + 1;
			w[counter-2] <= changeEndian(mem_read_data); //-2 to account for delays
			counter <= counter + 1;
			state <= READ;
			if (counter>limit)begin
				counter <= 0;
				registers <= registers - limit;
				state <= PAD;
			end
		end
			
		PAD: begin
			if(current_block == 1)begin
				w[15] <= (size << 3); //append size
				if(size % 4 == 0)begin
					w[0] <= 32'h80000000; //full block of padding
				end
				if(limit < 16) begin
					if(size % 4 > 0)begin //if unfinished word need to magic
						w[limit-1] <= magic(w[limit-1]);
					end
					if(size % 4 == 0)begin //if finished word need to make w[limit] = 1 
						w[limit] <= 32'h80000000;
					end
				end
			end
			if(current_block == 2 && size % 4 > 0 && registers < 1)begin //unfinished last word
					w[limit-1] <= magic(w[limit-1]);
			end
			if(registers<16)begin //set limit for next block
				limit <= registers;
			end
			else begin
				limit <= 16;
			end
			a <= h0; //prep hash constants
			b <= h1;
			c <= h2;
			d <= h3;
			e <= h4;		
			f <= h5;
			g <= h6;
			h <= h7;
			state <= HASH;
		end

		HASH: begin
			if(opcode == 2'b00)begin //md5
				if(counter < 64)begin
					if(counter < 16)begin
						{a, b, c, d} <= md5_op(a, b, c, d, w[counter], counter);					
					end	
				end
				if(counter > 15)begin
					{a, b, c, d} <= md5_op(a, b, c, d, w[md5_g(counter)], counter);
				end				
				counter <= counter + 1;
				if(counter==64)begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					state <= POST_HASH;	
				end
			end				
			if(opcode == 2'b01)begin //sha1
				if(counter < 80)begin	
					if(counter < 16)begin
						//debug
						//$display("t == %d\n",t);
						{a,b,c,d,e} <= hash_op(a, b, c, d, e, w[counter], counter);
						counter <= counter + 1;
					end	
					if( counter >= 16)begin
						//debug
					  // $display("t == %d\n",t);
						{a,b,c,d,e} <= hash_op(a, b, c, d, e, ((w[counter-a1]^w[counter-b1]^w[counter-c1]^w[counter-d1])<<1 | 
						(w[counter-a1]^w[counter-b1]^w[counter-c1]^w[counter-d1])>>31), counter);
						w[counter-e1]<= ((w[counter-a1]^w[counter-b1]^w[counter-c1]^w[counter-d1])<<1 | 
						(w[counter-a1]^w[counter-b1]^w[counter-c1]^w[counter-d1])>>31);
						counter <= counter + 1;	
						if((((counter+1)-3)%16)==0)begin
							a1 <= a1 + 16;
						end
						if((((counter+1)-8)%16)==0)begin
							b1 <= b1 + 16;
						end	
						if((((counter+1)-14)%16)==0)begin
							c1 <= c1 + 16;
						end			
						if(((counter+1)%16)==0)begin
							d1 <= d1 + 16;
							e1 <= e1 + 16;					
						end						
					end	 
				end
				if (counter == 80)begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					h4 <= h4 + e;
					a1 <= 3;
					b1 <= 8;
					c1 <= 14;
					d1 <= 16;
					e1 <= 16;
					state <= POST_HASH;	
				end
			end
			if(opcode == 2'b10) begin //sha256
				if(counter < 64)begin
					if(counter < 16)begin		
						{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[counter], counter);
					end
					if(counter> 14 )begin
						w[15] <= w[0] + (rightrotate(w[1],   7) ^ rightrotate(w[1],  18) ^ (w[1]  >>  3)) +
						w[9] + (rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
						for (int i=0; i<15; i++) 
							w[i] <= w[i+1];	
					end
					if(counter > 15)begin
						{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], counter);
					end
					counter <= counter + 1;
				end
				if (counter == 64)begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					h4 <= h4 + e;
					h5 <= h5 + f;
					h6 <= h6 + g;
					h7 <= h7 + h;
					state <= POST_HASH;
				end
			end	
		end		
		
		POST_HASH:begin
				w[0] <= 0; //set block to zeros again
				w[1] <= 0;
				w[2] <= 0;
				w[3] <= 0; 
				w[4] <= 0; 
				w[5] <= 0;
				w[6] <= 0;
				w[7] <= 0;
				w[8] <= 0;
				w[9] <= 0;
				w[10] <= 0;
				w[11] <= 0;
				w[12] <= 0;
				w[13] <= 0;
				w[14] <= 0;
				w[15] <= 0;
				counter <= 0;
				current_block <= current_block - 1; //decrement block counter
				if(limit > 0)begin
					state <= READ;
					mem_addr <= mem_addr - 2;
				end
				if(limit < 1 )begin
					state <= PAD;
				end
				if(current_block == 1)begin
					state <= OUTPUT;
					//mem_addr <= temp_addr //uncomment if doing more than one hash
				end
		end	
			
		OUTPUT:begin	
		    mem_we <= 1;
		    mem_addr <= output_addr; //comment out if doing more than one hash
			 if(counter == 0)begin
				mem_write_data <= h0;
			 end
			 if(counter == 1)begin
				mem_write_data <= h1;
			 end	
			 if(counter == 2)begin
				mem_write_data <= h2;
			 end	
			 if(counter == 3)begin
			 mem_write_data<=h3;
				if (opcode == 2'b00) begin
					state <= DONE;
				end
			 end	
			 if(counter==4)begin
				mem_write_data <= h4;
			 	if (opcode == 2'b01)begin
					state <= DONE;
				end
			 end
			 if(counter == 5)begin
				mem_write_data <= h5;
			 end		
			 if(counter == 6)begin
				mem_write_data <= h6;
			 end				
			 if(counter == 7)begin
				mem_write_data <= h7;
				if (opcode == 2'b10)begin
					state <= DONE;
				end
			 end				 
          mem_addr <= output_addr + counter;
			 counter <= counter + 1;
			 //temp_address <= output_addr + counter; //uncomment if doing more than one hash
			 
		end	 
			
      DONE: begin
		/* //debug
			$display("-------- FINAL RESULT --------");		
			$display("h0== %x\n",h0);
			$display("h1 == %x\n",h1);
			$display("h2 == %x\n",h2);
			$display("h3 == %x\n",h3);
			$display("h4 == %x\n",h4);
	   */		
         done <= 1;
         state <= SETUP;
		end	
      endcase
end		
  endmodule