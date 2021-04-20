# ws-protocol

websocket protocol

## Sec-WebSocket-Key

```rust
extern crate ws_protocol;

use ws_protocol::gen_sec_websocket_key;

fn main() {
    let sec_web_socket_key = gen_sec_websocket_key();
    println!("{}", sec_web_socket_key);
}
```

## Sec-WebSocket-Accept

```rust
extern crate ws_protocol;

use ws_protocol::get_sec_websocket_accept;
use ws_protocol::gen_sec_websocket_key;

fn main() {
    let sec_web_socket_key = gen_sec_websocket_key();
    let sec_web_socket_accept = get_sec_websocket_accept(&sec_web_socket_key);
    println!("{}", sec_web_socket_accept);
}
```