# junkNAS

## Configuration quickstart

The configuration file is JSON. The most common source of confusion is the
`data_dirs` field:

* `data_dir` is the **primary backing directory** for file metadata and the
  passthrough backing store. This is where files appear on disk.
* `data_dirs` is an **array of directories** used for chunk storage. When
  provided, the first entry becomes the effective `data_dir` as well.
* If `data_dirs` is provided as a **string**, it is ignored. Use a JSON array.
* The maximum number of entries in `data_dirs` is 8.

### Single directory

```json
{
  "storage_size": "1G",
  "data_dir": "/home/user/.local/share/junknas/data",
  "mount_point": "/mnt/junknas",
  "web_port": 9090,
  "verbose": true,
  "enable_fuse": true,
  "daemon_mode": false,
  "wireguard": {
    "interface_name": "jnk0",
    "wg_ip": "10.99.0.42",
    "endpoint": "example.com:51820",
    "listen_port": 51820,
    "mtu": 1420
  },
  "bootstrap_peers": [
    "10.0.0.1:8080",
    "example.com:8080"
  ],
  "wg_peers": [
    {
      "public_key": "BASE64_PUBLIC_KEY_HERE",
      "endpoint": "10.0.0.1:51820",
      "wg_ip": "10.99.0.2",
      "persistent_keepalive": 25,
      "web_port": 8080
    }
  ]
}
```

### Multi-directory chunk storage

To spread chunks across multiple directories, set `data_dirs` to an array. The
first entry becomes the primary backing directory (the effective `data_dir`).
Include your metadata/backing location as the first entry if you want it to stay
on a specific disk.

```json
{
  "storage_size": "1G",
  "data_dirs": [
    "/home/user/.local/share/junknas/data",
    "/home/user/.local/share/junknas/data-secondary"
  ],
  "mount_point": "/mnt/junknas",
  "web_port": 9090,
  "verbose": true,
  "enable_fuse": true,
  "daemon_mode": false,
  "wireguard": {
    "interface_name": "jnk0",
    "wg_ip": "10.99.0.42",
    "endpoint": "example.com:51820",
    "listen_port": 51820,
    "mtu": 1420
  },
  "bootstrap_peers": [
    "10.0.0.1:8080",
    "example.com:8080"
  ],
  "wg_peers": [
    {
      "public_key": "BASE64_PUBLIC_KEY_HERE",
      "endpoint": "10.0.0.1:51820",
      "wg_ip": "10.99.0.2",
      "persistent_keepalive": 25,
      "web_port": 8080
    }
  ]
}
```

### Tips

* Always use a JSON array for `data_dirs` (even if it has just one entry).
* Ensure every directory exists and is writable by the junkNAS process.
* `bootstrap_peers` should point at the web server endpoints used for mesh sync.
* Configuration and WireGuard keys live under `$XDG_CONFIG_HOME/junkNAS` (or
  `~/.config/junkNAS`) for persistence.
