# After installation

- **VPN client config** is saved to `~/awg0-client-<name>.conf`. Import it into any AmneziaWG client app.
- **Web panel** listens on `127.0.0.1:8080` by default. Keep that localhost binding. Access it on the server at `http://127.0.0.1:8080`, or from your computer with `ssh -N -L 8080:127.0.0.1:8080 user@server` then open `http://localhost:8080`. For always-on remote access, put a TLS-terminating reverse proxy in front of the localhost listener on a private network — do **not** expose the panel directly on a public interface (see [web panel install](../web-panel/install.md)).
- Re-run `sudo ./amneziawg-install.sh` to add or remove VPN clients interactively.
- Check the web panel status at any time:
  ```bash
  ./amneziawg-web.sh status
  ```
  > The `status` command does not require `sudo`.

---
