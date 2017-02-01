use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::io::SeekFrom;
use std::str;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::path::Path;
use std::net;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time;
use std::cmp;

extern crate bip_bencode;
extern crate hyper;
extern crate sha1;

use bip_bencode::{Bencode,Dictionary};

const HOST : &'static str = "127.0.0.1";
const PORT : u16 = 6882;
const MAX_PEERS : usize = 10;
const PEER_ID : [u8 ; 20] = [0 ; 20]; // TODO use a real peer id

enum event {
  started,
  stopped,
  finished
}

impl event {
  fn to_string(&self) -> String {
    match *self {
      event::started => "started",
      event::stopped => "stopped",
      event::finished => "finished"
    }.to_string()
  }
}

#[derive(Debug)]
enum message<'a> {
  choke,
  unchoke,
  interested,
  uninterested,
  have(u32),
  bitfield(&'a [u8]),         // MSB (b << 7) corresponds to piece 0
  request(u32, u32, u32),     // index, offset, length
  piece(u32, u32, &'a [u8]),  // index, offset, block (subset of piece)
  cancel(u32, u32, u32),      // index, offset, length
}

#[derive(Clone)]
struct response {
  interval: u64,
  complete: u64,
  incomplete: u64,
  peers: Vec<(net::Ipv4Addr, u16)>,
}

#[derive(Debug, Clone)]
struct peer<'a> {
  torrent: &'a torrent<bool>,
  
  host: net::Ipv4Addr,
  port: u16,
  tlc: Option<time::Instant>, // time of last contact
  
  choked: bool,       // if the peer is choked by us
  interesting: bool,  // if the peer is interesting to us
  
  choking: bool,      // if the peer is choking us
  interested: bool,   // if the peer is interested in us

  // TODO: this maybe could be a bit smaller... use a bitfield perhaps?
  pieces: Vec<(Option<bool>, &'a [u8; 20])>
}

/* torrent files have two modes, single file and multiple file, in the single file
   case root is the name of the file and file(u64) is the length, in the multiple
   file case, root is the name of the top level directory and directory() contains
   an ordered mapping from lengths to paths, so you can see how each file maps to
   a piece */
#[derive(Debug, Clone)]
enum path {
  file(u64),
  directory(Vec<(u64, PathBuf)>) /* length * path */
}

/* T is the type of piece annotations - before we know if we have a piece or not,
   we annotate with T=(), afterwards we can annotate with bool */
#[derive(Debug, Clone)]
struct info<T> {
  hash: [u8; 20],
  length: u32,
  pieces: Vec<(T, [u8; 20])>,
  // in single-file mode this is the file name, in directory mode it is the root dir
  name: String,
  path: path
}

#[derive(Debug, Clone)]
struct torrent<T> {
  announce: String,
  root: String,
  info: info<T>
}

impl path {
  fn parse(d : &Dictionary<Bencode>) -> Option<path> {
    match d.lookup("length".as_bytes()).and_then(Bencode::int) {
      // single file mode
      Some(length) => return Some(path::file(length as u64)),
      // multiple file mode
      // TODO: what do we do about broken (not valid UTF-8) text encoding?
      None => d.lookup("files".as_bytes()).and_then(Bencode::list).and_then(|files| {
        let mut v = Vec::new();
        
        for f in files.iter() {
          if f.dict().and_then(|fd| {
            fd.lookup("length".as_bytes()).and_then(Bencode::int).and_then(|length| {
              fd.lookup("path".as_bytes()).and_then(Bencode::list).and_then(|path_list| {
                let mut path = PathBuf::new();
                
                for p in path_list.iter() {
                  match p.bytes().and_then(|a| str::from_utf8(a).ok()) {
                    None => return None,
                    Some(s) => {
                      path.push(s);
                    }
                  }
                };
                
                return Some(v.push((length as u64, path)));
              })
            })
          }).is_none() { return None };
        }

        return Some(path::directory(v));
      })
    }
  }
}

impl<T> torrent<T> {
  // empty annotation () - we will fill that in later
  fn parse(buffer: &[u8], root: &str) -> Option<torrent<()>> {
    Bencode::decode(buffer).ok().and_then(|d| {
      d.dict().and_then(|dict| {
        dict.lookup("announce".as_bytes()).and_then(Bencode::bytes).and_then(|a| str::from_utf8(a).ok()).and_then(|announce| {
          dict.lookup("info".as_bytes()).and_then(|info_bencode| {
            info_bencode.dict().and_then(|info_dict| {
              info_dict.lookup("name".as_bytes()).and_then(Bencode::bytes).and_then(|a| str::from_utf8(a).ok()).and_then(|name| {
                info_dict.lookup("piece length".as_bytes()).and_then(Bencode::int).and_then(|length| {
                  info_dict.lookup("pieces".as_bytes()).and_then(Bencode::bytes).and_then(|pieces| {
                    path::parse(info_dict).and_then(|path| {
                      let mut ps = Vec::new();
                      for p in pieces.chunks(20) {
                        let mut a = [0; 20];
                        a.copy_from_slice(p);
                        ps.push(((), a));
                      };
                      
                      let mut h = sha1::Sha1::new();
                      h.update(&info_bencode.encode());
                      
                      Some(torrent {
                        announce: announce.to_string(),
                        root: root.to_string(),
                        info: info {
                          hash: h.digest().bytes(),
                          length: length as u32,
                          pieces: ps,
                          name: name.to_string(),
                          path: path
                        }
                      })
                    })
                  })
                })
              })
            })
          })
        })
      })
    })
  }

  // transforms a piece index into a list of files that the piece spans over
  // returns vector of (offset, length, path), the idea being to write a piece at index i
  // to disk, you call this function and get a vector {(o0, l0, p0), (o1, l1, p1), ...},
  // and then write the first l0 bytes of the piece to p0 at offset o0, and then l1 bytes
  // of the piece at offset l0 to p1 at offset o1 - also works for reading
  // ---
  // takes: offset, length into piece table, returns: offset of first file, index of first
  // file in path directory table, number of files to write to, and length of write to last
  // file in path directory table
  // so that's: offset, index, # of files, length
  fn file(&self, o : u64, l : u64) -> (u64, u64, u64, u64) {
    match self.info.path {
      path::file(l) => panic!("Error: called file() on file\n"), //return self.root.push(0, l, self.info.name),
      path::directory(ref ds) => {
        let mut offset = 0;
        let mut index = 0; // file index
        let mut p = 0; // sum of all file lengths up to this point

        while o > p + ds[index].0 {
          p += ds[index].0;
          index += 1;
        };

        offset = o - p;

        // at this point, index is the largest file whose start in the piece index table is smaller than our offset

        let mut n = 0;
        let mut q = p;
//        print!("asdf {} {} {} {} {}\n", o + l, q, p, index, ds[index].0);

        while (index + n < ds.len() - 1) && (o + l > q + ds[index + n].0) {
//          print!("loop {} {}\n", o + l, q);
          q += ds[index + n].0;
          n += 1;
        }

        // at this point, index is the smallest file whose end in the piece index table is larger than our offset + length

        // p + ds[index] should be the end of the smallest file whose end in the piece table index is larger than our offset + length (the file that our block ends in)
        let length = if n > 0 {
          o + l - q
        } else {
          0
        };

        return (offset, index as u64, n as u64, length);
      }
    };
  return (0,0,0,0);
  }

  // FIXME: no directory support (need file <-> hash mapping?)
  // FIXME: why is this so SLOW?!?!? maybe it needs to have a larger buffer...
  // should either: succeed, return IO exception, complain about file length mismatch
  // note: consumes self!
  fn check(self) -> Result<torrent<bool>, io::Error> {
    let mut b = vec![0; self.info.length as usize];
    let mut pieces : Vec<(bool, [u8; 20])> = Vec::new();

    match self.info.path {
      path::file(length) => {
        let mut p = PathBuf::from(self.root.clone());
        p.push(self.info.name.clone());
        let mut h = try!(File::open(p));
        assert!(length == try!(h.metadata()).len());  // TODO: find nicer way to enforce this

        for i in 0..self.info.pieces.len() {
          try!(self.read_piece(i as u64, &mut b));
          pieces.push((self.check_piece(i as u64, &b), self.info.pieces[i].1));
        };
      },
      path::directory(_) => {
        for i in 0..self.info.pieces.len() {
          try!(self.read_piece(i as u64, &mut b));
          pieces.push((self.check_piece(i as u64, &b), self.info.pieces[i].1));
        };
      }
    };

    return Ok(torrent {
      root: self.root,
      announce: self.announce,
      info: info {
        hash: self.info.hash,
        length: self.info.length,
        pieces: pieces,
        name: self.info.name,
        path: self.info.path
      }
    });
  }

  // should either: set v to the correct piece, and set its length to either piece_length
  // or length - (<number of pieces> * <piece_length>), or return an IO error
  // NO file length checking or any other sanity checking!
  fn read_piece(&self, i : u64, mut v : &mut Vec<u8>) -> Result<(), io::Error> {
    match self.info.path {
      path::file(length) => {
        let mut p = PathBuf::from(self.root.clone());
        p.push(self.info.name.clone());
        let mut h = try!(File::open(p));
        try!(h.seek(SeekFrom::Start(i * self.info.length as u64)));
        
        // last piece is a special case as it is smaller than piece length
        if i == (self.info.pieces.len() - 1) as u64 {
          v.truncate((length - i * self.info.length as u64) as usize);
        } else if v.len() != self.info.length as usize {
          v.resize(self.info.length as usize, 0);
        }
        
        try!(h.read_exact(&mut v));
      },
      path::directory(ref ds) => {
//        print!("In read_piece path::directory block\n");
        // piece size
        let s = {
          if i == (self.info.pieces.len() as usize - 1) as u64 {
            // calculate the size of the end piece
            let mut sps = 0;
            for d in ds {
              sps += d.0 as u32;
            };
            sps - ((i * self.info.length as u64) as u32)
          } else { //(v.len() != self.info.length as usize) {
            self.info.length
          }
        };

        if s != v.len() as u32 {
          v.resize(s as usize, 0);
        };
        
        let (o, ix, n, l) = self.file(i * self.info.length as u64, s as u64);

        let r = {
          let mut p = PathBuf::from(self.root.clone());
          p.push(self.info.name.clone());
          p
        };

        // read beginning of piece from first file
        let mut p = r.clone();
        p.push(&ds[ix as usize].1);
        let mut h = try!(File::open(&p));
        try!(h.seek(SeekFrom::Start(o)));

        // if the length of the file minus our offset into it is larger than our
        // piece size, then we should only read s number of bytes, otherwise read
        // to the end of the file
        let mut br : usize = cmp::min(s as usize, (ds[ix as usize].0 - o) as usize);
        //print!("br initial value: {}\n", br);
        try!(h.read_exact(&mut v[0..br as usize]));
        
    //    print!("In read_piece path::directory block, past first read\n");

        //assert!(r as u64 == ds[ix as usize].0 - o);

        if n > 1 {
          for ox in ix+1..ix+n-1 {
            let mut p = r.clone();
            p.push(&ds[ox as usize].1);
            //    print!("In read_piece path::directory block, in n>0 block, n={}\n, in loop, ox={}, path={}", n, ox, p);
            let mut h = try!(File::open(&p));
            try!(h.read_exact(&mut v[br..br+ds[ox as usize].0 as usize]));
            br += ds[ox as usize].0 as usize;
          };
        };
          
        if n > 0 {
          //print!("In n>0 block\n");
          let mut p = r.clone();
          p.push(&ds[(ix+n) as usize].1);
          let mut h = try!(File::open(&p));
          try!(h.read_exact(&mut v[br..br+l as usize]));
        };

        //print!("In read, i={}, br={}, l={}, s={}, br+l=s = {}\n", i, br, l, s, (br+l as usize)==s as usize);
        assert!(br+l as usize  == s as usize);
      }
    };

    return Ok(());
  }

  // asserts v is the correct size for piece i
  fn write_piece(&self, i : u64, v : Vec<u8>) -> Result<(), io::Error> {
    let mut p = PathBuf::from(self.root.clone());
    p.push(self.info.name.clone());

    match self.info.path {
      path::file(length) => {
        let mut h = try!(File::open(p));
        try!(h.seek(SeekFrom::Start(i * self.info.length as u64)));
        
        // last piece is a special case as it is smaller than piece length
        if i == (self.info.pieces.len() - 1) as u64 {
          assert!(v.len() == ((length - i * self.info.length as u64) as usize));
        } else if v.len() != self.info.length as usize {
          assert!(v.len() == self.info.length as usize);
        }
        
        try!(h.write_all(&v));
      },
      path::directory(_) => panic!("Not implemented: write_piece() on path::directory\n")
    };

    return Ok(());
  }

  // assume the piece is already in v, and i is the index of the piece v is supposed to be
  fn check_piece(&self, i : u64, v : &Vec<u8>) -> bool {
    let mut m = sha1::Sha1::new();
    m.update(&v);
    return (self.info.pieces[i as usize].1 == m.digest().bytes());
  }
}

impl torrent<bool> {
  fn announce(&self, c : hyper::Client) -> Option<response> {
    let mut url = hyper::Url::parse(&self.announce).unwrap();

    // append_pair only takes UTF-8 encoded strings, while our hash/peer id are not UTF-8 encoded strings, so we have to do our own escaping/URL construction:
    url.set_query(Some(&format!("info_hash={}&peer_id={}", &escape_hash(&self.info.hash), &escape_hash(&PEER_ID))));

    let mut left = 0;
    for i in self.info.pieces.iter() {
      if !i.0 {
        left += 1;
      }
    }
    left *= self.info.length;

    // FIXME!!!!! don't hardcode port!!!!
    url.query_pairs_mut().append_pair("port", &PORT.to_string());
    url.query_pairs_mut().append_pair("uploaded", "0");
    url.query_pairs_mut().append_pair("downloaded", "0");
    url.query_pairs_mut().append_pair("left", &left.to_string());
    url.query_pairs_mut().append_pair("compact", "1");
    url.query_pairs_mut().append_pair("no_peer_id", "0");
    url.query_pairs_mut().append_pair("event", &event::started.to_string());

    return c.get(url.as_str()).send().ok().and_then(|mut r| {
      let mut rs = Vec::new();
      r.read_to_end(&mut rs);

      response::parse(rs)
    });
  }
}

impl response {
  // FIXME make optional fields optional
  fn parse(v : Vec<u8>) -> Option<response> {
    return Bencode::decode(&v).ok().and_then(|r| {
      r.dict().and_then(|dict| {
        dict.lookup("interval".as_bytes()).and_then(Bencode::int).and_then(|interval| {
          dict.lookup("complete".as_bytes()).and_then(Bencode::int).and_then(|complete| {
            dict.lookup("incomplete".as_bytes()).and_then(Bencode::int).and_then(|incomplete| {
              dict.lookup("peers".as_bytes()).and_then(Bencode::bytes).and_then(|peers| {
                response::parse_peers(peers).and_then(|peers| {
                  Some(response {
                    interval: interval as u64,
                    complete: complete as u64,
                    incomplete: incomplete as u64,
                    peers: peers
                  })
                })
              })
            })
          })
        })
      })
    });
  }

  // FIXME this only does IPv4 (but then so does the tracker)
  fn parse_peers(v : &[u8]) -> Option<Vec<(net::Ipv4Addr, u16)>> {
    let mut r = Vec::new();

    // the peers field of the tracker response is an array of 6-byte values representing a 4-byte IPv4 address in network byte order followed by a 2-byte port number
    for c in v.chunks(6) {
      r.push((net::Ipv4Addr::new(c[0], c[1], c[2], c[3]), ((c[4] as u16) << 8) | (c[5] as u16)));
    }

    return Some(r)
  }
}

impl<'a> peer<'a> {
  fn new(h : net::Ipv4Addr, p : u16, t : &torrent<bool>) -> peer {
    let mut ps = Vec::new();
    for p in t.info.pieces.iter() {
      ps.push((None, &p.1));
    }
    
    return peer {
      torrent: &t,

      host: h,
      port: p,
      tlc: None,

      choked: true,
      interesting: false,
      choking: true,
      interested: false,

      pieces: ps
    };
  }

  // TODO: return None on incorrect length
  fn parse(o : u8, p : &Vec<u8>) -> Option<message> {
    Some(match o {
      0 => message::choke,
      1 => message::unchoke,
      2 => message::interested,
      3 => message::uninterested,
      4 => message::have(from_big_endian_u32(&p[0..4])),
      5 => message::bitfield(&p[1..]),
      6 => message::request(from_big_endian_u32(&p[0..4]), from_big_endian_u32(&p[4..8]), from_big_endian_u32(&p[8..12])),
      7 => message::piece(from_big_endian_u32(&p[0..4]), from_big_endian_u32(&p[4..8]), &p[9..]),
      8 => message::cancel(from_big_endian_u32(&p[0..4]), from_big_endian_u32(&p[4..8]), from_big_endian_u32(&p[8..12])),
      _ => { return None; }
    })
  }

  // returns whether handshake was successful
  fn handshake(&self, s : &mut TcpStream, b : &mut Vec<u8>) -> bool {
    s.write(&[19]); // length of the string "BitTorrent protocol"
    s.write(b"BitTorrent protocol");
    s.write(&[0 ; 8]);
    s.write(&self.torrent.info.hash);
    s.write(&PEER_ID);

    b.resize(68, 0);
    s.read_exact(&mut *b);

    return ((b[0] == 19) & (&b[1..20] == b"BitTorrent protocol") & (&b[28..48] == &self.torrent.info.hash));
  }

  // TODO: less copy paste
  fn choke(&mut self, s : &mut TcpStream) {
    self.choked = true;
    
    s.write(&to_big_endian_u32(1));
    s.write(&[0]);
  }

  fn unchoke(&mut self, s : &mut TcpStream) {
    self.choked = false;
    
    s.write(&to_big_endian_u32(1));
    s.write(&[1]);
  }

  fn interested(&mut self, s : &mut TcpStream) {
    self.interesting = true;

    s.write(&to_big_endian_u32(1));
    s.write(&[2]);
  }

  fn uninterested(&mut self, s : &mut TcpStream) {
    self.interesting = false;

    s.write(&to_big_endian_u32(1));
    s.write(&[3]);
  }

  fn have(&mut self, s : &mut TcpStream, i : u32) {
    s.write(&to_big_endian_u32(5));
    s.write(&[4]);
    s.write(&to_big_endian_u32(i));
  }

//  fn bitfield(&self, s : &mut TcpStream) {
//    let 
//  }
}

fn escape_char(c : &u8) -> String {
  // [^\-\.0-9A-Z_a-z~]
  if ((*c < 48) | ((*c > 57) & (*c < 65)) | ((*c > 90) & (*c < 97)) | (*c > 122)) & ((*c != 45) & (*c != 95) & (*c != 126)){
    return format!("%{:02X}", *c)
  } else {
    // above conditional should ensure this always succeeds
    return str::from_utf8(&[*c]).unwrap().to_string();
  }
}

fn escape_hash(h : &[u8]) -> String {
  let mut v = Vec::new();
  v.extend_from_slice(h);
  return v.iter().map(escape_char).collect::<String>();
}

// TODO these should be a macro (or maybe it's in std?)
fn to_big_endian_u32(n : u32) -> [u8; 4] {
  // DCBA -> ABCD
  [((n & 0xFF000000) >> 24) as u8,
   ((n & 0x00FF0000) >> 16) as u8,
   ((n & 0x0000FF00) >> 8) as u8,
   ((n & 0x000000FF) >> 0) as u8]
}
fn from_big_endian_u32(n : &[u8]) -> u32 {
  ((n[0] as u32) << 24) | ((n[1] as u32) << 16) | ((n[2] as u32) << 8) | (n[3] as u32)
}

fn main() {
  let args = std::env::args().collect::<Vec<String>>();
  let (file, root) = match (args.get(1), args.get(2)) {
    (Some(file), Some(root)) => (file, root),
    _ => panic!("Usage: ./torrent <path to .torrent file> <path to download location>")
  };
  
  let b = {
    let mut buffer = Vec::new();

    let mut f = match File::open(file) {
      Ok(v) => v,
      Err(e) => panic!("Error: File open error.\n")
    };
    
    match f.read_to_end(&mut buffer) {
      Ok(v) => v,
      Err(e) => panic!("Error: File read error.\n")
    };

    buffer
  };

  let mut t = {
    match torrent::<()>::parse(&b, root) {
      Some(t) => match t.check() {
        Ok(v) => v,
        Err(e) => panic!("Error: Check error: {}\n", e)
      },
      None => panic!("Error: Parse failure.\n")
    }
  };

  for i in 0..t.info.pieces.len() {
    print!("Piece: {}, have: {}, file: {:?}\n", i, t.info.pieces[i].0, t.file((t.info.length * i as u32) as u64, t.info.length as u64));
  };
  
  print!("t.info.path: {:?}\n", t.info.path);
  print!("file: {:?}\n", t.file(0, 12132352));
  
  let c = hyper::Client::new();
  let r = match t.announce(c) {
    None => panic!("Error: Invalid response.\n"),
    Some(r) => r
  };
  let mut ps = Vec::new();
  // FIXME: there has to be some way to keep this in ps?!?!
  // hack to get around borrow checker not liking vectors of tuples with mutable parts
  let mut ss = Vec::new();
  for a in r.peers.iter() {
    let mut s = match TcpStream::connect((a.0, a.1)) {
      Err(e) => {
        print!("Warning: Peer connection failure, host={}, port={}, error={}\n", a.0, a.1, e);
        continue;
      },
      Ok(v) => v
    };
    
    ps.push(peer::new(a.0, a.1, &t));
    ss.push(s);
  }

  let mut b = vec![0; 68];
  let mut gs = Vec::new();  // garbage peers, to close their connections later

  for i in 0..ps.len() {
    print!("In handshake, peer: {}:{}\n", &ps[i].host, ps[i].port);
    // TODO: remove peers who fail handshakes
    if !ps[i].handshake(&mut ss[i], &mut b) {
      print!("Warning: Handshake failure for peer {}:{}, received {:?}\n", ps[i].host, ps[i].port, b);
      gs.push(i);
    };
  };

  let mut sb = [0 ; 4];     // message size buffer (4 byte unsigned big endian integer)
  let mut ob = [0];         // message opcode buffer (1 byte unsigned integer)
  let mut pb = b;           // message payload buffer
  let mut rb = Vec::new();  // read buffer, for responding to block request messages
                            // we can't use pb for this because our parsed message might point to it

  let l = match TcpListener::bind((HOST, PORT)) {
    Ok(l) => l,
    Err(e) => panic!("Error: Could not listen on address {}:{}, error: {}\n", HOST, PORT, e)
  };

  // TODO: a few of these blocks could probably be moved into their own functions
  loop {
    // collect garbage peers
    // reverse sort so that we remove indices from the top down, so that we don't
    // shift indices of elements that we haven't removed yet
    gs.sort_by(|b, a| a.cmp(b));
    for g in 0..gs.len() {
      ss[gs[g]].shutdown(net::Shutdown::Both);
      ss.remove(gs[g]);
      ps.remove(gs[g]);
    };
    gs.clear();

    for ref p in &ps {
      print!("In loop after garbage peer collection, peer: {}:{}\n", p.host, p.port);
    };
//    print!("Right before incoming loop, l.incoming.len()={}\n", l.incoming().iter().len());
    // add new incoming connections to peers
    /*
    for c in l.incoming() {
      match c {
        Ok(mut c) => match c.peer_addr() {
          Ok(a) => match a {
            net::SocketAddr::V4(a) => {
              print!("Info: Peer incoming from {}:{}\n", a.ip(), a.port());

              let p = peer::new(*a.ip(), a.port(), &t);

              if p.handshake(&mut c, &mut pb) {
                ss.push(c);
                ps.push(p);
              } else {
                print!("Warning: Handshake failure for peer {}:{}, received {:?}\n", p.host, p.port, pb);
              }
            },
            net::SocketAddr::V6(_) => {
              print!("Info: Received IPv6 Address {}\n", a);
              continue;
            }
          },
          Err(e) => {
            print!("Warning: Socket address lookup failed, error={}\n", e);
          }
        },
        Err(e) => {
          print!("Warning: Incoming connection failed, error={}\n", e);
        }
      }
    }*/
    print!("Right before networking loop\n");
    for i in 0..cmp::min(ps.len(), MAX_PEERS) {
      print!("In networking loop for peer {}:{}\n", &ps[i].port, ps[i].port);
      // read message size
      match ss[i].read_exact(&mut sb).err() {
        Some(e) => {
          print!("Warning: Read failure for peer {}:{}, error: {}\n", ps[i].host, ps[i].port, e);
          gs.push(i);
          continue;
        },
        None => ()
      };
      let s = from_big_endian_u32(&sb);

      // keepalive
      // TODO: store time of last contact
      if s == 0 {
        continue;
      };

      // read opcode
      match ss[i].read_exact(&mut ob).err() {
        Some(e) => {
          print!("Warning: Read failure for peer {}:{}, error: {}\n", ps[i].host, ps[i].port, e);
          continue;
        },
        None => ()
      };

      // minus opcode
      pb.resize((s - 1) as usize, 0);

      // read message payload
      match ss[i].read_exact(&mut pb).err() {
        Some(e) => {
          print!("Warning: Read failure for peer {}:{}, error: {}\n", ps[i].host, ps[i].port, e);
          continue;
        },
        None => ()
      };

      let m = match peer::parse(ob[0], &pb) {
        Some(m) => m,
        None => {
          print!("Warning: Parse failure for peer {}:{}, size={}, opcode={}, payload={:?}\n", ps[i].host, ps[i].port, s, ob[0], pb);
          continue;
        }
      };

      print!("Info: Message: {:?} for peer: {}:{}\n", m, ps[i].host, ps[i].port);

      // TODO: move this to its own function, peer::interpret() maybe?
      match m {
        message::unchoke => {
          ps[i].choking = false;

          print!("In unchoke block\n");
          ps[i].unchoke(&mut ss[i]);

          // FIXME this is cheating!!
          for o in 0..t.info.pieces.len() {
            if t.info.pieces[o].0 {
              ps[i].have(&mut ss[i], o as u32);
            };
          };
        },
        message::interested => {
          ps[i].interested = true;

          // FIXME this is cheating!!
          for o in 0..t.info.pieces.len() {
            if t.info.pieces[o].0 {
              ps[i].have(&mut ss[i], o as u32);
            };
          };
        },
        message::bitfield(f) => {
          for o in 0..f.len() {
            for n in 0..8 {
              // TODO: proper error handling
              assert!(o + (7 - n) <= ps[i].pieces.len());
              // the MSB of the first byte, f[0] & (1 << 7), corresponds to piece 0
              ps[i].pieces[o + (7 - n)].0 = Some(1 == f[o] & (1 << (7 - n)));
            };
          };
        },
        message::request(x, o, l) => {  // x for piece index, o for offset, l for length
          //print!("In request, i={}, o={}, l={}, length={}, pieces={}\n", i, o, l, t.info.length, t.info.pieces.len());
          // TODO: proper error handling
          assert!(x < t.info.pieces.len() as u32);
          assert!(o + l <= t.info.length);
          t.read_piece(x as u64, &mut rb);

          let mut rv_mid = &mut rb.split_at(o as usize);
          let rv = rv_mid.1.split_at(l as usize).0;
          
          ss[i].write(&to_big_endian_u32(1 + 4 + 4 + l)); // message + index + offset + block length
          ss[i].write(&[7]);
          ss[i].write(&to_big_endian_u32(x));
          ss[i].write(&to_big_endian_u32(o));
          ss[i].write(&rv);
        }
        _ => print!("Warning: Unimplemented message: message={:?}\n", m)
      };

      ss[i].flush();
    };
  };
}