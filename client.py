import socket
from betanet_ref import (
    AccessTicketParams, AccessTicketClient, InnerCryptoState, Frame, hkdf_expand, sha256
)

def main(str):
    host = "127.0.0.1"
    port = 65432

    # Load server's public key and key id
    with open("ticket_pub.bin", "rb") as f:
        server_ticket_pub = f.read()
    with open("ticket_key_id.bin", "rb") as f:
        ticket_key_id = f.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("[Client] Connected to server.")

        params = AccessTicketParams(ticket_pub=server_ticket_pub, ticket_key_id=ticket_key_id, carrier_policy={'cookie':1.0})
        client = AccessTicketClient(params)
        payload = client.build_cookie_value()
        s.sendall(payload)

        response = s.recv(1024)
        if response != b"OK":
            print(f"[Client] Server rejected access ticket: {response.decode()}")
            return
        print("[Client] Access ticket accepted.")

        tls_exporter = sha256(b"tls-exporter-demo")
        K0 = hkdf_expand(tls_exporter, b"htx inner v1", 64)
        state = InnerCryptoState(K0)

        #plaintext = b"Hello from the client!"
        plaintext = input("[Client] Enter message to send: ").encode()

        
        # The AAD must be the same on both client and server
        aad = b"stream-meta"
        
        ct = state.seal_stream(is_client=True, plaintext=plaintext, associated_data=aad)
        frame = Frame(Frame.TYPE_STREAM, stream_id=1, ciphertext=ct)
        packed = frame.pack()
        s.sendall(packed)
        print("[Client] Sent encrypted message.")

if __name__ == "__main__":
    while True:
        try:
            main("")
        except Exception as e:
            print(f"[Client] Error: {e}")
        except KeyboardInterrupt:
            print("[Client] Exiting.")
            break
