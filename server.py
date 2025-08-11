import socket
import threading
from betanet_ref import AccessTicketServer, InnerCryptoState, Frame, hkdf_expand, sha256
from cryptography.hazmat.primitives.asymmetric import x25519
import secrets

def handle_client(conn, addr, server_ticket_priv_key, ticket_key_id):
    print(f"[Server] Connection from {addr}")
    try:
        server = AccessTicketServer(server_ticket_priv_key, ticket_key_id)
        
        payload = conn.recv(1024)
        if not payload:
            print("[Server] No payload received for access ticket.")
            return

        ok, reason = server.verify_cookie_payload(payload)
        if not ok:
            print(f"[Server] Access ticket verification failed: {reason}")
            return
        print("[Server] Access ticket verified.")
        conn.sendall(b"OK")


        tls_exporter = sha256(b"tls-exporter-demo")
        K0 = hkdf_expand(tls_exporter, b"htx inner v1", 64)
        state = InnerCryptoState(K0)

        packed_frame = conn.recv(1024)
        if not packed_frame:
            print("[Server] No frame received.")
            return
            
        unpacked, used = Frame.unpack(packed_frame)
        
        aad = b"stream-meta" 
        
        decrypted = state.open_stream(is_client=False, ciphertext=unpacked.ciphertext, associated_data=aad)
        
        print(f"[Server] Decrypted message: {decrypted.decode()}")

    except Exception as e:
        print(f"[Server] Error handling client: {e}")
    finally:
        conn.close()

def main():
    host = "127.0.0.1"
    port = 65432

    server_ticket_priv_key = x25519.X25519PrivateKey.generate()
    ticket_key_id = secrets.token_bytes(8)

    with open("ticket_pub.bin", "wb") as f:
        f.write(server_ticket_priv_key.public_key().public_bytes(
            encoding = __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
            format = __import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw
        ))
    with open("ticket_key_id.bin", "wb") as f:
        f.write(ticket_key_id)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[Server] Listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, server_ticket_priv_key, ticket_key_id))
            client_thread.start()

if __name__ == "__main__":
    main()
