# Upgrading and rolling back the BoringTun binary

```bash
# Move to the BoringTun release this installer version pins
sudo ./amneziawg-install.sh --upgrade-boringtun

# Go back to the release that was current before
sudo ./amneziawg-install.sh --rollback-boringtun
```

**Explicit only.** Running a newer `amneziawg-install.sh` never switches the binary, and
neither does anything else it does: clients, protocol changes, imitation changes and the menu
leave the installed release alone. A host installed by an earlier version, with
`boringtun-cli-0.7.1-g71d88784ad29-b1`, `boringtun-cli-0.7.1-gae2ab44e9a68-b1` or
`boringtun-cli-0.7.1-gb94943906b11-b1`, keeps running that release until `--upgrade-boringtun`
moves it to the one this version pins; until then `--backend-status` reports
`upgrade_available=yes`. The first two have no imitation mode `auto`, although they report the
same version (`0.7.1`) as the others: the installer asks the binary itself and refuses `auto` on
them (see [Built-in protocol imitation](imitation.md)).
`gb94943906b11` has `auto`, so a rollback to it keeps `auto`, without the newer learning from
datagrams that also fit the AmneziaWG framing.

**What each command targets.**
- **Upgrade:** only the release pinned in the installer itself, never a "latest" lookup.
  Moving to a newer BoringTun means a newer installer with a reviewed pin.
  - When the pin is already installed, its links are consistent and the helper scripts are
    up to date, the upgrade changes nothing.
  - When the pin is already installed but the helper scripts are older, the upgrade only
    refreshes them and says so. A stopped service stays stopped, and a running one is not
    restarted for it.
  - If an interrupted switch left `previous` naming the same release, the upgrade removes only
    that link. Any older release directory stays, unmanaged, and is never guessed back as the
    rollback target.
- **Rollback:** only the release that was current before the last upgrade or rollback. It
  takes no release argument.

The store manages at most two releases, `current` and `previous`, so two rollbacks in a row
toggle back and forth. Other release directories can remain, for example after an
interrupted switch. They are unmanaged: reported, never used, never removed automatically.

Both commands first refresh the installer's two generated helper scripts, because helpers
from earlier versions don't accept the names of later builds. That includes an upgrade that
finds the pin already installed.

**What a switch does.**
1. The upgrade downloads and verifies the pinned release exactly as a fresh install does,
   beside the running one.
2. Before anything changes, the target binary is validated on temporary instances against this
   server as it is now:
   - the current AWG protocol mode;
   - the protocol imitation;
   - the server config and every client config.

   A rollback is refused, without changing anything, when the older binary does not accept
   today's settings (for example a protocol mode enabled after the upgrade). With imitation
   `auto` configured, a rollback to a binary without it is refused before anything else:
   select a fixed imitation or `none` first, then roll back.
3. `current` and `previous` are switched atomically, and an active service is restarted and
   checked: the right binary, its TUN device, UAPI, listen port, imitation and peers.
4. A stopped or failed service is switched but not started.
5. If the restart or the check fails, both links are restored and the previous binary is
   restarted and checked.

Params, client configs, the imitation and the listen port never change.

**Status.** `--backend-status` adds:
- `previous_release`, `rollback_available` and `upgrade_available`. `rollback_available=yes`
  means a previous release is there, passes the store check and runs the configured imitation
  (`auto` needs a binary that has it); the rollback itself still validates it against today's
  settings and can refuse;
- `daemon_release`, the release the running daemon executes, which shows a service that still
  runs an old binary;
- `unmanaged_releases`: release directories neither link names, which are reported but never
  removed automatically;
- `imitation_auto_support`: `supported`, `unsupported` or `unknown`, whether the installed
  binary runs imitation `auto`, from the binary's own answer.

**Builds.** A later build of the same BoringTun source commit (for example `-b2`) is stored
under its own name, so it can sit beside build 1. Hosts installed before this version keep
their store as it is.
