## ICMP Tunneling (Advanced)

Follow these steps to create and run the advanced ICMP tunneling script.

1. Create the ICMP tunneling script, for example:

```bash
nano icmp_tunnel_advanced.py
```

2. Create a tunneling payload and save it (inside the script or as a separate file, depending on your design).

3. Make the script executable:

```bash
chmod +x icmp_tunnel_advanced.py
```

4. Run the script (may require root privileges):

```bash
sudo python3 icmp_tunnel_advanced.py
```

5. Live view: the script prints activity to the terminal. All activity is also logged to a file:

```
icmp_tunnel.log
```

To view the log at any time:

```bash
cat icmp_tunnel.log
tail -f icmp_tunnel.log    # live monitoring
```

Notes
- Ensure you have the proper permissions and that running network tunneling tools complies with local laws and policies.
- Running as root may be required to create raw ICMP sockets.