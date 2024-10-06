use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::cmp::min;
use std::string::FromUtf8Error;
use std::str;

const GAME_HEADER: &[u8] = b"Hock";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Addresses
    let proxy_addr: SocketAddr = "0.0.0.0:27590".parse()?;
    let dest_addr: SocketAddr = "85.143.172.20:27585".parse()?;

    // Create a UDP socket for the proxy
    let proxy_socket = Arc::new(UdpSocket::bind(proxy_addr).await?);
    println!("Proxy listening on {}", proxy_addr);

    // Create a UDP socket for the destination server
    let dest_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    dest_socket.connect(dest_addr).await?;
    println!("Connected to destination server at {}", dest_addr);

    // Store client addresses and their corresponding buffers
    let clients: Arc<Mutex<HashMap<SocketAddr, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let mut buf = [0; 1024];
        let (len, client_addr) = proxy_socket.recv_from(&mut buf).await?;

        println!("Received {} bytes from {}", len, client_addr);
        
        // Spawn a new task to handle this client's request
        let proxy_socket = Arc::clone(&proxy_socket);
        let dest_socket = Arc::clone(&dest_socket);
        let clients = Arc::clone(&clients);

        tokio::spawn(async move {
            handle_client(proxy_socket, dest_socket, clients, client_addr, &buf[..len]).await;
        });
    }
}

async fn handle_client(
    proxy_socket: Arc<UdpSocket>,
    dest_socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<SocketAddr, Vec<u8>>>>,
    client_addr: SocketAddr,
    data: &[u8],
) {
    if let Err(e) = dest_socket.send(data).await {
        eprintln!("Failed to send data to destination server: {}", e);
        return;
    }

    // Store the client address and buffer
    let mut clients = clients.lock().await;
    clients.insert(client_addr, data.to_vec());
    

    // Receive response from the destination server
    let mut buf = [0; 1024];
    let resp_len = match dest_socket.recv(&mut buf).await {
        Ok(len) => len,
        Err(e) => {
            eprintln!("Failed to receive data from destination server: {}", e);
            return;
        }
    };

    let mut parser = HQMMessageReader::new(&buf);
    let header = parser.read_bytes_aligned(4);
    if header != GAME_HEADER {
        eprintln!("Wrong game header: {:?}", header);
        return;
     }

    let command = parser.read_byte_aligned();
    
    match command {
        1 => {
            let server_name_data = buf[12..buf.len()].to_vec(); 
            let server_name= String::from_utf8(server_name_data).expect("Found invalid UTF-8");

            let new_server_name = format!("[Proxy] {}",server_name);

            let new_server_name_data = new_server_name.as_bytes();
            let new_server_name_vec = new_server_name_data.to_vec();

            for i in 12..buf.len() {
                buf[i] = new_server_name_vec[i - 12];
            }
        }
        _ => {}
    }

    // Send the response back to the original client
    if let Err(e) = proxy_socket.send_to(&buf[..resp_len], client_addr).await {
        eprintln!("Failed to send data back to client: {}", e);
    }
    
    // Remove the client from the map
    // clients.remove(&client_addr);
}

fn get_server_name(bytes: Vec<u8>) -> Result<String, FromUtf8Error> {
    let first_null = bytes.iter().position(|x| *x == 0);

    let bytes = match first_null {
        Some(x) => &bytes[0..x],
        None => &bytes[..],
    }
    .to_vec();
    let name = String::from_utf8(bytes)?;
    Ok(if name.is_empty() {
        "Noname".to_owned()
    } else {
        name
    })
}

pub struct HQMMessageReader<'a> {
    buf: &'a [u8],
    pos: usize,
    bit_pos: u8,
}

impl<'a> HQMMessageReader<'a> {
    #[allow(dead_code)]
    pub fn get_pos(&self) -> usize {
        self.pos
    }

    fn safe_get_byte(&self, pos: usize) -> u8 {
        if pos < self.buf.len() {
            self.buf[pos]
        } else {
            0
        }
    }

    pub fn read_byte_aligned(&mut self) -> u8 {
        self.align();
        let res = self.safe_get_byte(self.pos);
        self.pos = self.pos + 1;
        return res;
    }

    pub fn read_bytes_aligned(&mut self, n: usize) -> Vec<u8> {
        self.align();

        let mut res = Vec::with_capacity(n);
        for i in self.pos..(self.pos + n) {
            res.push(self.safe_get_byte(i))
        }
        self.pos = self.pos + n;
        return res;
    }

    pub fn read_u16_aligned(&mut self) -> u16 {
        self.align();
        let b1: u16 = self.safe_get_byte(self.pos).into();
        let b2: u16 = self.safe_get_byte(self.pos + 1).into();
        self.pos = self.pos + 2;
        return b1 | b2 << 8;
    }

    pub fn read_u32_aligned(&mut self) -> u32 {
        self.align();
        let b1: u32 = self.safe_get_byte(self.pos).into();
        let b2: u32 = self.safe_get_byte(self.pos + 1).into();
        let b3: u32 = self.safe_get_byte(self.pos + 2).into();
        let b4: u32 = self.safe_get_byte(self.pos + 3).into();
        self.pos = self.pos + 4;
        return b1 | b2 << 8 | b3 << 16 | b4 << 24;
    }

    pub fn read_f32_aligned(&mut self) -> f32 {
        let i = self.read_u32_aligned();
        return f32::from_bits(i);
    }

    #[allow(dead_code)]
    pub fn read_pos(&mut self, b: u8, old_value: Option<u32>) -> u32 {
        let pos_type = self.read_bits(2);
        match pos_type {
            0 => {
                let diff = self.read_bits_signed(3);
                let old_value = old_value.unwrap() as i32;
                (old_value + diff).max(0) as u32
            }
            1 => {
                let diff = self.read_bits_signed(6);
                let old_value = old_value.unwrap() as i32;
                (old_value + diff).max(0) as u32
            }
            2 => {
                let diff = self.read_bits_signed(12);
                let old_value = old_value.unwrap() as i32;
                (old_value + diff).max(0) as u32
            }
            3 => self.read_bits(b),
            _ => panic!(),
        }
    }

    #[allow(dead_code)]
    pub fn read_bits_signed(&mut self, b: u8) -> i32 {
        let a = self.read_bits(b);

        if a >= 1 << (b - 1) {
            (-1 << b) | (a as i32)
        } else {
            a as i32
        }
    }

    pub fn read_bits(&mut self, b: u8) -> u32 {
        let mut bits_remaining = b;
        let mut res = 0u32;
        let mut p = 0;
        while bits_remaining > 0 {
            let bits_possible_to_write = 8 - self.bit_pos;
            let bits = min(bits_remaining, bits_possible_to_write);

            let mask = if bits == 8 {
                u8::MAX
            } else {
                !(u8::MAX << bits)
            };
            let a = (self.safe_get_byte(self.pos) >> self.bit_pos) & mask;
            let a: u32 = a.into();
            res = res | (a << p);

            if bits_remaining >= bits_possible_to_write {
                bits_remaining -= bits_possible_to_write;
                self.bit_pos = 0;
                self.pos += 1;
                p += bits;
            } else {
                self.bit_pos += bits_remaining;
                bits_remaining = 0;
            }
        }
        return res;
    }

    pub fn align(&mut self) {
        if self.bit_pos > 0 {
            self.bit_pos = 0;
            self.pos += 1;
        }
    }

    #[allow(dead_code)]
    pub fn next(&mut self) {
        self.pos += 1;
        self.bit_pos = 0;
    }

    pub fn new(buf: &'a [u8]) -> Self {
        HQMMessageReader {
            buf,
            pos: 0,
            bit_pos: 0,
        }
    }
}
