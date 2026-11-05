# After installation

- **VPN client config** is saved to `~/awg0-client-<name>.conf`. Import it into any AmneziaWG client app.
- **Web panel** listens on `127.0.0.1:8080` by default. Access it on the server at `http://127.0.0.1:8080`, or change `AWG_WEB_LISTEN` / use a reverse proxy for remote access.
- Re-run `sudo ./amneziawg-install.sh` to add or remove VPN clients interactively.
- Check the web panel status at any time:
  ```bash
  ./amneziawg-web.sh status
  ```
  > The `status` command does not require `sudo`.

---
