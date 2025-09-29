//クレートの呼び出し部分です
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;

//VER(プロトコルバージョン)を指定するものです。
const SOCKS5_VERSION: u8 = 5;
//認証不要のために定義されている値（X'00'）です。
const NO_AUTH_METHOD: u8 = 0x00;
//受け入れられるメソッドがないことを示す値（X'FF'）です。
const NO_ACCEPTABLE_METHOD: u8 = 0xFF;

//リクエストのフォーマットです。
//CMD（コマンド）, 宛先アドレス（ATYP+ADDR）, 宛先ポート（PORT）が保持されます。
#[derive(Debug, Clone)]
struct Request {
    command: Command,
    address: Address,
    port: u16,
}

//各ATYP（アドレスタイプ）に対応する列挙型です。
#[derive(Debug, Clone)]
enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

//各CMD（コマンド）の列挙型です。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Unknown(u8),
}

//REP（リプライフィールド）の列挙型です。
//エラー内容は必要に応じて拡張可能です。
#[derive(Debug, Copy, Clone)]
enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
}

//リクエストに基づいて宛先にTCP接続を行います。
impl Request {
    fn connect(&self) -> io::Result<TcpStream> {
        match &self.address {
            Address::Ipv4(addr) => {
                TcpStream::connect(SocketAddr::new(IpAddr::V4(*addr), self.port))
            }
            Address::Ipv6(addr) => {
                TcpStream::connect(SocketAddr::new(IpAddr::V6(*addr), self.port))
            }
            Address::Domain(host) => TcpStream::connect((host.as_str(), self.port)),
        }
    }
}

//ログ出力用の部分です。
impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}:{}", self.command, self.address, self.port)
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ipv4(addr) => write!(f, "{addr}"),
            Address::Ipv6(addr) => write!(f, "[{addr}]"),
            Address::Domain(host) => write!(f, "{host}"),
        }
    }
}
impl From<u8> for Command {
    fn from(code: u8) -> Self {
        match code {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            other => Command::Unknown(other),
        }
    }
}
impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Connect => write!(f, "CONNECT"),
            Command::Bind => write!(f, "BIND"),
            Command::UdpAssociate => write!(f, "UDP ASSOCIATE"),
            Command::Unknown(code) => write!(f, "UNKNOWN(0x{code:02X})"),
        }
    }
}
impl Reply {
    fn code(self) -> u8 {
        self as u8
    }
}

//---ここからメインの関数です。---
fn main() -> io::Result<()> {
    //8080ポートで待ち受けます。
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("SOCKS5 proxy listening on {}", listener.local_addr()?);

    //接続を受け付けます。
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                thread::spawn(move || {
                    if let Some(peer) = peer {
                        println!("Accepted connection from {peer}");
                    } else {
                        println!("Accepted connection from unknown peer");
                    }

                    if let Err(err) = handle_client(stream) {
                        eprintln!("Client error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("Failed to accept connection: {err}"),
        }
    }

    Ok(())
}

//接続の処理本体
fn handle_client(mut client: TcpStream) -> io::Result<()> {
    //1. メソッドの交渉: クライアントが提示するメソッドを受信します。
    let methods = read_greeting(&mut client)?;
    println!("Client supports methods: {}", describe_methods(&methods));

    //2. 認証方式の選択: 今回は認証不要のみとします。
    if !methods.contains(&NO_AUTH_METHOD) {
        send_method_selection(&mut client, NO_ACCEPTABLE_METHOD)?;
        return Err(io::Error::new(
            ErrorKind::Other,
            "client did not offer the no-authentication method",
        ));
    }

    // 認証不要で応答します。
    send_method_selection(&mut client, NO_AUTH_METHOD)?;

    //リクエストを読み取ります
    let request = read_request(&mut client)?;
    println!("Request: {request}");

    //CONNECTについてのみ今回は実装します。そのためCONNECT以外はここでエラーを返します。
    if request.command != Command::Connect {
        send_reply(&mut client, Reply::CommandNotSupported, None)?;
        return Err(io::Error::new(
            ErrorKind::Other,
            "only CONNECT command is supported",
        ));
    }

    //宛先にTCP接続します。
    let remote = match request.connect() {
        Ok(stream) => stream,
        Err(err) => {
            //失敗時は一般的な失敗の応答をします。
            send_reply(&mut client, Reply::GeneralFailure, None)?;
            return Err(err);
        }
    };

    //ここから成功応答の記述です。
    let bound_addr = remote
        .local_addr()
        .unwrap_or_else(|_| default_bound_address());
    send_reply(&mut client, Reply::Succeeded, Some(bound_addr))?;

    //双方向中継の記述です。
    bridge(client, remote)?;
    println!("Finished forwarding {request}");
    Ok(())
}

//クライアントの一番最初のGreeting（VER, NMETHODS, METHODS…）を読み取ります。
fn read_greeting(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;

    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported SOCKS version: {}", header[0]),
        ));
    }

    let count = header[1] as usize;
    let mut methods = vec![0u8; count];
    stream.read_exact(&mut methods)?;
    Ok(methods)
}

// サーバのメソッド選択応答（VER, METHOD）を送信します。
fn send_method_selection(stream: &mut TcpStream, method: u8) -> io::Result<()> {
    stream.write_all(&[SOCKS5_VERSION, method])?;
    stream.flush()
}

// リクエスト（CONNECT 等）の読み取り部分です。
// クライアントの要求（VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT）を解析して Request を返します。
fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;

    //VER 検証
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported SOCKS version: {}", header[0]),
        ));
    }

    //CMD 識別
    let command = Command::from(header[1]);

    // RSVが0であることを確認します
    if header[2] != 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "reserved byte must be zero",
        ));
    }

    // ATYP に基づき DST.ADDR を可変長で読み取ります
    let address = match header[3] {
        0x01 => {
            //IPv4は4バイトです
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        0x03 => {
            //DOMAINはLEN(1バイト)+ドメイン名です
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut domain = vec![0u8; length[0] as usize];
            stream.read_exact(&mut domain)?;
            Address::Domain(String::from_utf8_lossy(&domain).into_owned())
        }
        0x04 => {
            //IPv6は16バイトです
            let mut segments = [0u8; 16];
            stream.read_exact(&mut segments)?;
            Address::Ipv6(Ipv6Addr::from(segments))
        }
        value => {
            //変なATYPがくればエラーを返します
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unsupported address type: 0x{value:02X}"),
            ));
        }
    };

    //DST.PORTはビッグエンディアン2バイトです
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(Request {
        command,
        address,
        port,
    })
}

// 応答（REP）を送信します
// 成功/失敗応答（VER, REP, RSV, ATYP, BND.ADDR, BND.PORT）を組み立てて送信します。
fn send_reply(stream: &mut TcpStream, reply: Reply, bound: Option<SocketAddr>) -> io::Result<()> {
    // 十分な容量を確保します。（最大で IPv6 + ポート）
    let mut response = Vec::with_capacity(4 + 16 + 2);
    response.push(SOCKS5_VERSION); //VER
    response.push(reply.code()); //REP
    response.push(0x00); //RSV(0)

    // 応答の BND はサーバ側のバインドアドレス（None の場合は 0.0.0.0:0）
    let bound_addr = bound.unwrap_or_else(default_bound_address);
    match bound_addr {
        SocketAddr::V4(addr) => {
            response.push(0x01); // ATYP=IPv4
            response.extend_from_slice(&addr.ip().octets()); // BND.ADDR
            response.extend_from_slice(&addr.port().to_be_bytes()); // BND.PORT
        }
        SocketAddr::V6(addr) => {
            response.push(0x04); // ATYP=IPv6
            response.extend_from_slice(&addr.ip().octets()); // BND.ADDR
            response.extend_from_slice(&addr.port().to_be_bytes()); // BND.PORT
        }
    }

    stream.write_all(&response)?;
    stream.flush()
}

//双方向中継の記述です。
// クライアント <-> 宛先 を同時に中継します。
// 1) client -> remote を別スレッドで copy
// 2) main スレッドで remote -> client を copy
// 3) それぞれ終了後、対応方向に Shutdown を適用し、綺麗にクローズします。
fn bridge(mut client: TcpStream, mut remote: TcpStream) -> io::Result<()> {
    // 送受を分けるためにクローンしておきます。
    let mut client_reader = client.try_clone()?;
    let mut remote_writer = remote.try_clone()?;

    //client -> remote 方向の転送を別スレッドで実行します
    let forward = thread::spawn(move || -> io::Result<()> {
        let copied = io::copy(&mut client_reader, &mut remote_writer)?;
        println!("Forwarded {copied} bytes client -> remote");
         // 送信側を終了（書き込み側を閉じる）し、受信側は読み取りを閉じます
        let _ = remote_writer.shutdown(Shutdown::Write);
        let _ = client_reader.shutdown(Shutdown::Read);
        Ok(())
    });

    // remote -> client 方向を転送します（こちらは現スレッド）
    let copied_back = io::copy(&mut remote, &mut client)?;
    println!("Forwarded {copied_back} bytes remote -> client");
    let _ = client.shutdown(Shutdown::Write);
    let _ = remote.shutdown(Shutdown::Read);

    // 別スレッドの終了を待ちます
    match forward.join() {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            ErrorKind::Other,
            "forwarding thread panicked",
        )),
    }
}

//ログ出力用の部分です。
fn describe_methods(methods: &[u8]) -> String {
    if methods.is_empty() {
        return "none".to_string();
    }

    let parts: Vec<String> = methods
        .iter()
        .map(|&code| describe_auth_method(code))
        .collect();
    parts.join(", ")
}
fn describe_auth_method(code: u8) -> String {
    match code {
        NO_AUTH_METHOD => "No Authentication".to_string(),
        0x01 => "GSSAPI".to_string(),
        0x02 => "Username/Password".to_string(),
        other => format!("Unknown(0x{other:02X})"),
    }
}
fn default_bound_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}