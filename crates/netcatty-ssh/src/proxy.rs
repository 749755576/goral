use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::{NormalizedProxyConfig, ProxyType, TransportError, TransportErrorCode};

const MAX_HTTP_PROXY_HEADER_BYTES: usize = 32 * 1024;

pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) async fn connect_proxy(
    proxy: &NormalizedProxyConfig,
    target_host: &str,
    target_port: u16,
    password: Option<&str>,
) -> Result<Box<dyn AsyncStream>, TransportError> {
    match proxy.proxy_type {
        ProxyType::Http => {
            let mut stream = connect_network_proxy(proxy).await?;
            http_connect(&mut stream, proxy, target_host, target_port, password).await?;
            Ok(Box::new(stream))
        }
        ProxyType::Socks5 => {
            let mut stream = connect_network_proxy(proxy).await?;
            socks5_connect(&mut stream, proxy, target_host, target_port, password).await?;
            Ok(Box::new(stream))
        }
        ProxyType::Command => Ok(Box::new(spawn_proxy_command(
            proxy,
            target_host,
            target_port,
        )?)),
    }
}

async fn connect_network_proxy(proxy: &NormalizedProxyConfig) -> Result<TcpStream, TransportError> {
    let host = proxy.host.as_deref().ok_or_else(proxy_failed)?;
    let port = proxy.port.ok_or_else(proxy_failed)?;
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|_| proxy_failed())?;
    stream.set_nodelay(true).map_err(|_| proxy_failed())?;
    Ok(stream)
}

async fn http_connect(
    stream: &mut TcpStream,
    proxy: &NormalizedProxyConfig,
    target_host: &str,
    target_port: u16,
    password: Option<&str>,
) -> Result<(), TransportError> {
    validate_http_token(target_host)?;
    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let (Some(username), Some(password)) = (proxy.username.as_deref(), password) {
        if username.contains(['\r', '\n']) {
            return Err(proxy_failed());
        }
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| proxy_failed())?;

    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while header.len() < MAX_HTTP_PROXY_HEADER_BYTES {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|_| proxy_failed())?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err(proxy_failed());
    }
    let status_line = header
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !(status_line.starts_with(b"HTTP/1.1 200") || status_line.starts_with(b"HTTP/1.0 200")) {
        return Err(proxy_failed());
    }
    Ok(())
}

async fn socks5_connect(
    stream: &mut TcpStream,
    proxy: &NormalizedProxyConfig,
    target_host: &str,
    target_port: u16,
    password: Option<&str>,
) -> Result<(), TransportError> {
    let has_credentials = proxy.username.is_some() && password.is_some();
    let greeting: &[u8] = if has_credentials {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .await
        .map_err(|_| proxy_failed())?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|_| proxy_failed())?;
    if method[0] != 0x05 {
        return Err(proxy_failed());
    }
    match method[1] {
        0x00 => {}
        0x02 if has_credentials => {
            socks5_authenticate(
                stream,
                proxy.username.as_deref().unwrap_or_default(),
                password.unwrap_or_default(),
            )
            .await?;
        }
        _ => return Err(proxy_failed()),
    }

    let host = target_host.as_bytes();
    let host_len = u8::try_from(host.len()).map_err(|_| proxy_failed())?;
    let mut request = Vec::with_capacity(host.len() + 7);
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_len]);
    request.extend_from_slice(host);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| proxy_failed())?;

    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| proxy_failed())?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(proxy_failed());
    }
    let address_len = match response[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|_| proxy_failed())?;
            usize::from(length[0])
        }
        _ => return Err(proxy_failed()),
    };
    let mut ignored = vec![0_u8; address_len + 2];
    stream
        .read_exact(&mut ignored)
        .await
        .map_err(|_| proxy_failed())?;
    Ok(())
}

async fn socks5_authenticate(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), TransportError> {
    let username = username.as_bytes();
    let password = password.as_bytes();
    let username_len = u8::try_from(username.len()).map_err(|_| proxy_failed())?;
    let password_len = u8::try_from(password.len()).map_err(|_| proxy_failed())?;
    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[0x01, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .await
        .map_err(|_| proxy_failed())?;
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| proxy_failed())?;
    if response != [0x01, 0x00] {
        return Err(proxy_failed());
    }
    Ok(())
}

fn spawn_proxy_command(
    proxy: &NormalizedProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<CommandProxyStream, TransportError> {
    let command = substitute_proxy_command(
        proxy.command.as_deref().unwrap_or_default(),
        target_host,
        target_port,
    )?;
    if command.trim().is_empty() {
        return Err(proxy_failed());
    }
    let mut process = if cfg!(windows) {
        let mut process = Command::new("cmd.exe");
        process.args(["/D", "/S", "/C", &command]);
        process
    } else {
        let mut process = Command::new("sh");
        process.args(["-c", &command]);
        process
    };
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| proxy_failed())?;
    let stdin = child.stdin.take().ok_or_else(proxy_failed)?;
    let stdout = child.stdout.take().ok_or_else(proxy_failed)?;
    Ok(CommandProxyStream {
        child,
        stdin,
        stdout,
    })
}

#[must_use = "the substituted command must be checked for errors"]
pub fn substitute_proxy_command(
    command: &str,
    target_host: &str,
    target_port: u16,
) -> Result<String, TransportError> {
    let quoted_host = quote_shell_argument(target_host)?;
    let quoted_port = quote_shell_argument(&target_port.to_string())?;
    let mut output = String::with_capacity(command.len() + target_host.len());
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        match chars.peek().copied() {
            Some('%') => {
                chars.next();
                output.push('%');
            }
            Some('h') => {
                chars.next();
                output.push_str(&quoted_host);
            }
            Some('p') => {
                chars.next();
                output.push_str(&quoted_port);
            }
            _ => output.push('%'),
        }
    }
    Ok(output)
}

fn quote_shell_argument(value: &str) -> Result<String, TransportError> {
    if cfg!(windows) {
        // `cmd.exe /S /C` has several metacharacters whose meaning is not
        // reliably neutralized by surrounding quotes (notably `^`, `&`,
        // pipes, redirections and parenthesized command groups).  Reject
        // them in substituted endpoint values instead of trying to emulate
        // cmd.exe's context-sensitive escaping rules.  The user-authored
        // proxy command remains supported; only `%h`/`%p` values are bounded.
        if value.chars().any(|character| {
            matches!(
                character,
                '\0' | '\r'
                    | '\n'
                    | '"'
                    | '%'
                    | '!'
                    | '^'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '`'
            )
        }) {
            return Err(proxy_failed());
        }
        Ok(format!("\"{value}\""))
    } else {
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    }
}

struct CommandProxyStream {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for CommandProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(context, buffer)
    }
}

impl AsyncWrite for CommandProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stdin).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_shutdown(context)
    }
}

impl Drop for CommandProxyStream {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn validate_http_token(value: &str) -> Result<(), TransportError> {
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(proxy_failed());
    }
    Ok(())
}

fn proxy_failed() -> TransportError {
    TransportError::new(TransportErrorCode::ProxyFailed, "SSH 代理连接或握手失败")
}

#[cfg(test)]
mod tests {
    use super::substitute_proxy_command;

    #[test]
    fn proxy_command_substitutes_openssh_tokens() {
        let command = substitute_proxy_command(
            "cloudflared access ssh --hostname %h --port %p --literal %%",
            "server.example.com",
            2222,
        )
        .expect("safe substitution");

        assert!(command.contains("server.example.com"));
        assert!(command.contains("2222"));
        assert!(command.ends_with("--literal %"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_substitution_rejects_cmd_metacharacters() {
        for value in [
            "host^name",
            "host&name",
            "host|name",
            "host<name",
            "host>name",
            "host(name)",
        ] {
            assert!(
                substitute_proxy_command("proxy %h", value, 22).is_err(),
                "{value}"
            );
        }
    }
}
