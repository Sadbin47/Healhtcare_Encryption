# WireGuard deployment for the healthcare API

WireGuard protects the transport path between a doctor workstation and the
application server. It does not replace:

```text
WireGuard        -> transport confidentiality and network isolation
AES-256-GCM      -> EHR confidentiality and integrity
ECC/ML-KEM       -> AES-key protection
Blockchain       -> record metadata and authorization state
Local consent    -> patient permission state
VPS storage -> encrypted-envelope storage
```

## Address plan

The examples use a private tunnel:

```text
Server wg0: 10.77.0.1/24
Doctor wg0: 10.77.0.2/32
API:        bind only to 10.77.0.1
```

Replace example keys and endpoint values during deployment. Never commit real
WireGuard private keys, preshared keys, RPC credentials, or TLS keys.

## Server setup

1. Install WireGuard on the VPS and generate a server key pair offline or with
   `wg genkey`/`wg pubkey`.
2. Fill `server.conf.example` and add one peer entry per authorized doctor.
3. Start `wg-quick@wg0` and enable it at boot.
4. Bind the healthcare API to `10.77.0.1` using:

   ```python
   create_server(
       "10.77.0.1",
       8443,
       api,
       vpn_network="10.77.0.0/24",
       vpn_interface_address="10.77.0.1",
   )
   ```

5. Allow the API port only on `wg0` in the VPS firewall. Keep SSH restricted
   to administration addresses and use HTTPS/TLS where the deployment exposes
   an HTTP API beyond the tunnel.

## Firewall example

Adapt to the VPS provider and existing firewall policy; do not blindly run
these commands on production:

```text
ufw deny 8443/tcp
ufw allow in on wg0 to 10.77.0.1 port 8443 proto tcp
ufw allow 51820/udp
```

The application-level CIDR check is an additional guard. The firewall remains
necessary because an application check does not replace host-level isolation.

## Doctor setup

Give each doctor a unique tunnel address and key pair. Use
`doctor.conf.example` as a template, restrict `AllowedIPs` to the healthcare
server subnet, and use `PersistentKeepalive` only when the doctor is behind a
NAT that requires it.

## Operational requirements

- Rotate peer keys and remove revoked peers from the server configuration.
- Keep the API, blockchain RPC, and storage administration endpoints off the
  public interface whenever possible.
- Treat VPN membership as network admission, not patient consent or doctor
  authorization.
- Record VPN configuration changes through the deployment change process.
