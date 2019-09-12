var art_DexFile_OpenMemory = Module.findExportByName('libart.so','_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_'); // art::DexFile::OpenMemory > 64bit version
console.log(art_DexFile_OpenMemory);
Interceptor.attach(art_DexFile_OpenMemory, { 
  onEnter: function (_args) {     
    var begin = this.context.x0;
    this.o = {};
    this.o.begin = begin;
    this.o.magic = Memory.readUtf8String(begin);
    var address = parseInt(begin, 16) + 0x20;
    var dexSize = Memory.readInt(ptr(address));
    this.o.dexSize = dexSize;
    var file = new File('/sdcard/unpack/' + dexSize + '.dex', 'wb');
    file.write(Memory.readByteArray(begin, dexSize));
    file.flush();
    file.close();
  },
  onLeave: function (retval) {
    this.o.retval = retval;
    console.log(JSON.stringify(this.o, null, 2));
  }
});
