# askVT
Read a csv file that contains hashes of _files_, then check if the _files_ are sane using the hashes against VirusTotal API 

# requirement
```
pip install python-dotenv requests
```

# How to run

`$ python3 <this program> <CSV file>`

* the <CSV file> should look like the below:

```
FILE NAME,FILE PATH,SHA256,MD5,SHA1
Readme.md,/some/path/to/the/file/Readme.md,eff881474fcbb1996d819c71dca378501f590cc9f97c15340f8a91eebd9bc5f7,34f2a5a570ea8c081897e897732c1ce5,1d5cb079804e737a75777d831a01d9f2c86598bb
Anexe.exe,/some/path/to/the/file/Anexe.exe,a4f98f0ad0d18dd96d2843dd32cb0d1c5985570d3789afe7f5f2dc3b7e4925ec,b3ec2f4190f05b226f085928ba223403,c31d93ec5564838176b40406e5bdc9b203364b33
BText.txt,/some/path/to/the/file/BText.txt,12f063a3ed0c90b2a971b672e16960b406bb5369b4006aa45d5806afc813f3d8,85216b67b9dfb0d6139495436f3143f6,783283ec05229ca02f3a948261eed2edf08497e9
```
