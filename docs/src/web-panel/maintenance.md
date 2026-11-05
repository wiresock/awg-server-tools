# Web panel maintenance

All web panel lifecycle actions use the same script:

**Upgrade the web panel:**

```bash
sudo ./amneziawg-web.sh upgrade
```

**Uninstall the web panel (keeps config and data):**

```bash
sudo ./amneziawg-web.sh uninstall --force
```

**Uninstall and purge all data:**

```bash
sudo ./amneziawg-web.sh uninstall --purge-config --purge-data --force
```

> The script works standalone — it automatically downloads required files when run.

---
