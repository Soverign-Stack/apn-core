# Installing an APN node

For a Linux computer with a 64-bit Intel or AMD processor (x86_64) that uses
systemd: Ubuntu, Debian, Fedora, Pop!_OS and most others. You need a user
account that can run `sudo`. It takes about five minutes.

You should have received a folder containing `apn_node` (the node program),
`install.sh`, `uninstall.sh`, `apn`, `apn-node.service` and `node.env.example`.

## 1. Install

Open a terminal in that folder and run:

    sudo ./install.sh

This copies the program to `/usr/local/bin`, creates a locked-down system user
called `apn` that the node runs as, and creates the settings file
`/etc/apn/node.env`. It downloads nothing and does not start the node.

If you were sent a checksum for `apn_node`, compare it first:
`sha256sum apn_node` must print the same value.

## 2. Settings

If you were given a relay address or a relay login, put them in the settings
file, then save:

    sudo nano /etc/apn/node.env

Otherwise leave the file as it is.

## 3. Start

    sudo systemctl enable --now apn-node.service

The node now runs in the background, starts again after a reboot, and restarts
itself if it fails.

## 4. Get the claim code

    sudo apn claim-code

It prints a code that looks like `ABCDE-FGH23`. Treat it like a password:
whoever enters it first becomes the owner of this node.

## 5. Enter the code in the Dashboard

Sign in to the Dashboard, open the page for adding a node, type the claim code
and give the node a name if you like. Do this while the node is running: the
Dashboard only accepts a code from a node it has heard from in the last ten
minutes. The node then appears in your organization's list of nodes.

## 6. Check status

    sudo apn status

A healthy node shows `Node process: running`, `Relay: CONNECTED` and a
`Last heartbeat` less than a minute old. The node cannot tell you whether it
has been claimed; the Dashboard shows that.

Other commands:

| Command | What it does |
|---|---|
| `sudo apn logs` | Recent log lines (`sudo apn logs -f` to follow) |
| `sudo apn restart` | Restart, needed after editing the settings file |
| `sudo apn stop` / `sudo apn start` | Stop or start the node |
| `sudo apn show-phrase` | Show the recovery phrase |

If status says `CONNECTING` or `DISCONNECTED`, the node keeps retrying by
itself. Check your internet connection and the relay address and login in the
settings file; `sudo apn logs` shows the reason for each failed attempt.

## Recovery phrase

The node's identity is 12 words stored in `/var/lib/apn`, readable only by the
`apn` user. Run `sudo apn show-phrase` once, write the words down and keep them
private. With them the same node identity can be restored on another machine.
The phrase is never written to the log.

## Privacy

Every 30 seconds the node sends a small signed message: its node id, its
public key, the time, the software version, three yes/no capability flags and
a fingerprint (hash) of the claim code. By default it does not send the
computer's name, hardware details or local network addresses. You can choose
to send the computer's name and hardware by setting `APN_SHARE_HARDWARE=1` in
the settings file.

## What the node does not do yet

- **No peer-to-peer connection.** The node does not talk to other nodes
  directly. Everything goes through our relay server (a message broker), over
  one outgoing connection. It opens no ports on your computer.
- **It holds no funds.** The node has no working wallet and cannot receive,
  hold or send tokens. Balances are kept per organization in the Dashboard.
- **No earnings.** Running a node does not pay rewards at this stage.
- **No work for others.** It does not relay other people's traffic, run their
  computations or store their data. It only reports that it is online.

## Uninstall

From the folder you installed from:

    sudo ./uninstall.sh

This stops the node and removes the program and the service. It keeps the
identity and settings, so installing again brings back the same node.

To also delete the identity, the claim code, the settings and the `apn` user
(this cannot be undone):

    sudo ./uninstall.sh --purge

Then remove the node from your organization in the Dashboard.
