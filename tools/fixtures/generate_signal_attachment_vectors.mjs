// Independent Node/OpenSSL reference vector for Signal's AES-CBC + HMAC layout.
// All keys and contents are synthetic. Run from any directory with Node.js.
import { createCipheriv, createHmac, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
const crc32=data=>{let c=0xffffffff;for(const value of data){c^=value;for(let i=0;i<8;i++)c=(c>>>1)^((c&1)?0xedb88320:0);}return(c^0xffffffff)>>>0;};
const chunk=(name,data)=>{const type=Buffer.from(name);const out=Buffer.alloc(data.length+12);out.writeUInt32BE(data.length);type.copy(out,4);data.copy(out,8);out.writeUInt32BE(crc32(Buffer.concat([type,data])),out.length-4);return out;};
const width=160,height=80,header=Buffer.alloc(13);header.writeUInt32BE(width,0);header.writeUInt32BE(height,4);header[8]=8;header[9]=2;
const pixels=Buffer.alloc(height*(width*3+1));for(let y=0;y<height;y++){for(let x=0;x<width;x++){const i=y*(width*3+1)+1+x*3;pixels[i]=35;pixels[i+1]=150;pixels[i+2]=180;}}
const plaintext=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(pixels)),chunk('IEND',Buffer.alloc(0))]);
const keys=Buffer.from(Array.from({length:64},(_,i)=>i));
const iv=Buffer.from(Array.from({length:16},(_,i)=>255-i));
const padded=Buffer.concat([plaintext,Buffer.alloc(Math.max(0,1024-plaintext.length))]);
const cipher=createCipheriv('aes-256-cbc',keys.subarray(0,32),iv);
const authenticated=Buffer.concat([iv,cipher.update(padded),cipher.final()]);
const file=Buffer.concat([authenticated,createHmac('sha256',keys.subarray(32)).update(authenticated).digest()]);
const sha=data=>createHash('sha256').update(data).digest('hex');
writeFileSync(new URL('../../tests/fixtures/signal-attachment.json',import.meta.url),JSON.stringify({
  key:keys.toString('base64'),plaintext:plaintext.toString('base64'),ciphertext:file.toString('base64'),
  plaintext_hex:plaintext.toString('hex'),ciphertext_hex:file.toString('hex'),
  plaintext_sha256:sha(plaintext),ciphertext_sha256:sha(file),size:plaintext.length,
},null,2)+'\n');
