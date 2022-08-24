
#[warn(unused_imports)]

use std::io::{BufReader, BufRead,Cursor};


use std::fs::OpenOptions;
use byteorder::{BigEndian, ReadBytesExt,LittleEndian};

struct Secone{
    offset : u32,
    size :u32,
}
struct Sectpe{
    name: u64,
    vsize: u32,
    voffset:u32,
    rsize:u32,
    ptor:u32,
    ptore:u32,
    ptoline:u32,
    n_re:u16,
    n_line:u16,
    character:u32,
}



struct o_heaer{
    sizeofcode : u32,
    sizeofu: u32,
    sizeofun : u32,
    entry:u32,
    baseofcode:u32,
    baseofdata:u32,
    imagebase:u32,
    sectionalignment:u32,
    filealignment:u32,
    majorv:u16,
    minorv:u16,
    majori:u16,
    minori:u16,
    majors:u16,
    minors:u16,
    w32v:u32,
    sizeofimage:u32,
    sizeofheaders:u32,
    checksum:u32,
    check:u16,
    dllc:u16,
    flags:u32,
    n_rva:u32

}



struct Pex{
    mz : u8  ,
    mz2 : u16,
    pe_postiton:u16,
    tag_pe:u32,
    machine:u16,
    n_sections:u16,
    time:u32,
    pts:u32,
    n_symbols:u32,
    n_oheaer:u16,
    character:u16,
    oo : o_heaer,

}

impl Pex{
    fn mymz(&self) -> u8{
        self.mz
    }
    fn yinit( &mut self,buf : &[u8]) {
        let mut  fnbuf=Cursor::new(buf);    
        self.mz2 = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.mz2 = fnbuf.read_u16::<LittleEndian>().unwrap();
        fnbuf.set_position(0x3c);
        self.pe_postiton=fnbuf.read_u16::<LittleEndian>().unwrap();
        fnbuf.set_position(self.pe_postiton.into());
        self.tag_pe=fnbuf.read_u32::<LittleEndian>().unwrap();
        self.machine=fnbuf.read_u16::<LittleEndian>().unwrap();
        self.n_sections=fnbuf.read_u16::<LittleEndian>().unwrap();
        self.time=fnbuf.read_u32::<LittleEndian>().unwrap();
        self.pts=fnbuf.read_u32::<LittleEndian>().unwrap();
        self.n_symbols=fnbuf.read_u32::<LittleEndian>().unwrap();
        self.n_oheaer=fnbuf.read_u16::<LittleEndian>().unwrap();
        self.character=fnbuf.read_u16::<LittleEndian>().unwrap();
        println!("pe pos {:#04x} {:#04x}",fnbuf.position(),(fnbuf.position() + self.n_oheaer as u64));
        let offset_sec :u64 = fnbuf.position() + self.n_oheaer as u64;

        fnbuf.set_position((self.pe_postiton + 20 + 4 +4).into());
        //self.mz2 = fnbuf.read_u16::<LittleEndian>().unwrap();
        //println!("pe pos 2 {:#04x}",fnbuf.position());
        self.oo.sizeofcode = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.sizeofu = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.sizeofun = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.entry = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.baseofcode = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.baseofdata = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.imagebase = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.sectionalignment = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.filealignment = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.majorv = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.oo.minorv = fnbuf.read_u16::<LittleEndian>().unwrap();        
        self.oo.majori = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.oo.minori  = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.oo.majors = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.oo.minors = fnbuf.read_u16::<LittleEndian>().unwrap();        
        self.oo.w32v = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.sizeofimage  = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.sizeofheaders  = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.checksum = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.check = fnbuf.read_u16::<LittleEndian>().unwrap();
        self.oo.dllc = fnbuf.read_u16::<LittleEndian>().unwrap();
        println!("pe pos 2 {:#04x}  ddlc {:#04x}",fnbuf.position(),self.oo.dllc);
       
        fnbuf.set_position(fnbuf.position()+0x20);
        self.oo.flags = fnbuf.read_u32::<LittleEndian>().unwrap();
        self.oo.n_rva = fnbuf.read_u32::<LittleEndian>().unwrap();
        
        println!("pe flag {:#04x}  rva {:#04x}",self.oo.flags,self.oo.n_rva);

       

        let mut t:Vec<Secone> = Vec::new();
        let mut s:Vec<Sectpe> = Vec::new();

        let mut sectpeone=Sectpe{name:0,vsize:0,voffset:0,rsize:0,ptor:0,ptore:0,ptoline:0,n_re:0,n_line:0,character:0};
        
        
        //let mut sone=Secone{offset:0,size:0};
        //sone.offset = fnbuf.read_u32::<LittleEndian>().unwrap();
        //sone.size  = fnbuf.read_u32::<LittleEndian>().unwrap();
        //t.push(sone);

        for i in 0..0x10{
            let mut sone=Secone{offset:0,size:0};
            sone.offset = fnbuf.read_u32::<LittleEndian>().unwrap();
            sone.size  = fnbuf.read_u32::<LittleEndian>().unwrap();
            t.push(sone);
        }
        for i in 0..self.n_sections{
            let mut sectpeone=Sectpe{name:0,vsize:0,voffset:0,rsize:0,ptor:0,ptore:0,ptoline:0,n_re:0,n_line:0,character:0};
            sectpeone.name= fnbuf.read_u64::<LittleEndian>().unwrap();
            sectpeone.vsize= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.voffset= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.rsize= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.ptor= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.ptore= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.ptoline= fnbuf.read_u32::<LittleEndian>().unwrap();
            sectpeone.n_re= fnbuf.read_u16::<LittleEndian>().unwrap();
            sectpeone.n_line= fnbuf.read_u16::<LittleEndian>().unwrap();
            sectpeone.character= fnbuf.read_u32::<LittleEndian>().unwrap();
            s.push(sectpeone);

        }
        println!("pe pos3 {:#04x}  ddlc {:#04x}",fnbuf.position(),self.oo.dllc);
        //println!("pe sizeofcode  {:#04x}",self.oo.sizeofcode);
        //println!("pe entry  {:#04x}",self.oo.entry);
        //println!("pe sizeofimage  {:#04x}",self.oo.sizeofimage);
        println!("pe n_rva  {:#04x} {:#04x}",self.oo.flags,self.oo.n_rva);
        println!("pe sizeof_o_header  {:#04x} {:#04x}",self.n_oheaer,offset_sec);
        println!("vec  {:#04x} {:#04x}",t.len(),s.len());
        println!("vec  1 {:#04x} ",t[0].offset);
        println!("vec  2 {:#04x} ",t[1].offset);
        println!("vvec  2 {:#04x} ",s[0].voffset);


    }

}

fn myread(buf : &[u8]){
    println!("{}" , buf[0]);
    let mut uoo=o_heaer{sizeofcode:0,sizeofu:0,sizeofun:0,entry:0,baseofcode:0,baseofdata:0,imagebase:0,sectionalignment:0,filealignment:0,
                                 majorv:0,minorv:0,majori:0,minori:0,majors:0,minors:0,w32v:0,sizeofimage:0,sizeofheaders:0,
                                 checksum:0,check:0,dllc:0,flags:0,n_rva:0};
    let mut pea=Pex{mz:0,mz2:0,pe_postiton:0,tag_pe:0,machine:0,n_sections:0,time:0,pts:0,n_symbols:0,n_oheaer:0,character:0,oo:uoo};
    let mut  fnbuf=Cursor::new(buf);
    pea.mz = buf[0];
    pea.mz2 = fnbuf.read_u16::<LittleEndian>().unwrap();
    println!("{} {}",pea.mz,pea.mz2);
    println!("{}",pea.mymz());
    pea.yinit(buf);
    println!("pe post {:#02x}",pea.pe_postiton);
    println!("pe tag {:#02x}",pea.tag_pe);
    println!("pe character {:#04x}",pea.character);
    println!("pe timestampe {:#04x}",pea.time);

}



fn main() {
   let path = std::env::args().nth(1).expect("no path given");

   let metadata = std::fs::metadata(&path).unwrap();
   let f1 = metadata.len();
   let f2 = f1;

   let file = OpenOptions::new().read(true).open(&path).unwrap();
   let   mut   reader = BufReader::with_capacity(f2.try_into().unwrap(),file);

    //
    println!("Hello, world! {} {} {}",&path,&reader.capacity(),f1);
    let   buffer = reader.fill_buf().unwrap();
    
    println!("{:?} {}",buffer.len(),& buffer[0]);

    myread(buffer);
   // let vv= f.into_inner();

}
