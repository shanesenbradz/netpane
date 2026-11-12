# Wi-Fi Security Audit (NetPane)

This is the operating guide for the Wi-Fi Audit panel in NetPane, and for the standalone wifi-bf desktop tool that sits alongside it in the project. The panel is defensive. It does not attack anything. It shows you how exposed a Wi-Fi network is and why, so you can fix it. The attack side of the project runs from the separate wifi-bf tool, against a network you own, and the two together tell the whole story: here is how the attack works, and here is the defence.

Tested on NetPane 1.6.0, Linux.

## What the panel is

NetPane already runs about thirty network tools behind one page. The Wi-Fi Audit panel adds a security view on top of the Wi-Fi data NetPane can already see. It has three parts: a list of nearby networks with the encryption each one uses, a passphrase strength tester, and a password-list check where you import an attacker wordlist and see whether a passphrase is in it.

Everything in the panel runs in your browser on your own machine. The passphrase you type and any wordlist you import never leave the computer. The only network call the panel makes is the same local Wi-Fi scan the rest of NetPane uses.

## Opening it

1. Start NetPane the normal way. On Linux that is `sudo python3 netpane.py`, which opens the page at `http://127.0.0.1:8765`.
2. In the left sidebar, click **Wi-Fi Audit**, or press Ctrl+9.

The nearby-networks list needs `nmcli` (the NetworkManager CLI) to read Wi-Fi. Most desktop Linux installs already have it. If NetPane says to install network-manager, the passphrase tester and the list check still work without it, because those two are pure client-side and do not depend on a scan.

## Part 1: nearby networks

This table is the same scan NetPane does elsewhere, read through a security lens. For each access point in range you get the SSID, channel, signal, and the encryption, with a plain-language note on what that encryption means.

The encryption tag is colour-coded the way the rest of NetPane colours things. WPA3 and WPA2 read green. WPA on its own (the dated first version) reads amber, because it should be upgraded. WEP and open networks read red. WEP is broken and crackable in minutes, and open means no encryption at all, so anyone in range can read the traffic.

Your own network, the one the laptop is currently joined to, is tagged "You're on this" so you can pick it out of the list quickly. For the project, that is the only row that matters. The other rows are neighbours and nearby businesses that the radio happens to hear, and you leave those alone.

## Part 2: passphrase strength

Type a passphrase into the box (use the eye button to show or hide it) and the meter and the readout update as you type. This is for testing your own Wi-Fi password, or a candidate you are thinking of using.

The readout gives you five numbers: length, the size of the character pool (lowercase adds 26, uppercase 26, digits 10, symbols about 33), the entropy in bits, the total number of guesses needed to exhaust that space, and an estimated time to crack.

The crack time depends on who is attacking you, so there is an **attacker model** dropdown. The default is a WPA2 handshake cracked offline on a GPU rig, at roughly a million guesses a second. WPA2 is slow to attack on purpose, because the key goes through PBKDF2 with 4096 iterations, so even a strong rig is limited. The second option, a single GPU, is slower again. The third option, a leaked fast hash like MD5 at a hundred billion guesses a second, is there to show how much weaker a password is when the attacker is not slowed down by Wi-Fi's key derivation. Switch between them and watch the same passphrase go from safe to crackable. That contrast is a good thing to demonstrate live.

One honest limitation, and it is worth stating in the writeup because it shows you understand the method. The entropy figure assumes the characters are random. A real person's password is not random, so for a human-chosen password this number is an overestimate. That is exactly why the next part exists.

## Part 3: password list check

This is the part that mirrors the brute-force attack directly. A dictionary attack does not try every possible combination. It tries a list of passwords people actually use, in order, and most weak Wi-Fi falls in the first pass. So the real question is not "how many bits is my password," it is "is my password on the list the attacker already has."

NetPane always checks a short built-in list of the most common passwords. To check against a real one, click **Import wordlist** and pick a `.txt` file. The obvious choice is the same list wifi-bf uses, the SecLists top 100,000 common passwords. Any plain-text list works, one password per line. After it loads, NetPane tells you how many it read, and from then on it checks every passphrase you type against that list live.

If a passphrase is in the list, the panel says so and marks it cracked instantly, because that is the truth: a dictionary attack reaches it in seconds. If it is not in the list, the panel says that too, and reminds you that strength then comes down to the numbers in Part 2.

There is also a batch box. Paste several candidate passphrases, one per line, press **Test these**, and you get a verdict for each. Handy if you want to show a row of weak passwords getting flagged next to a strong one.

## The desktop tool: wifi-bf

The attack side of the project is the wifi-bf tool, run on its own, not from inside NetPane. There are two helper scripts for it.

`wifibf-install.sh` sets it up on a fresh Linux box. It checks for git, python3 and curl and installs any that are missing, clones wifi-bf, downloads the wordlist, and writes the launcher. Run it once:

```bash
chmod +x wifibf-install.sh
./wifibf-install.sh
source ~/.bashrc
```

`wifibf-launch.sh` is the launcher it writes. After the install, you start the tool by typing `wifibf`. It makes sure the wordlist is present, then drops you at the target menu. Pass `-v` (as `wifibf -v`) to see every password it tries.

The target menu lists every access point the radio hears, including your neighbours. Pick the number next to your own SSID and nothing else. Running a brute-force against a network you do not own is not part of this project, it is unauthorised access, and the fact that the scanner can see a network does not make it fair to attack. The scripts deliberately do not auto-pick a target for this reason.

A note on the method itself. This pure-python tool works by repeatedly trying to associate to the access point with each password. That is slow and noisy, and your own router may lock you out for a while if you hammer it. The standard way this is taught, and the faster way, is to capture the WPA handshake once and then crack it offline against the same wordlist. If you go that route for the report, the handshake capture and offline crack is the cleaner demonstration, and it does not keep knocking on the live router.

## Putting it in the report

The strongest framing for the grade is attack then defence, on your own network end to end. You show the weakness with wifi-bf, then you show the countermeasure with the NetPane panel. Here is a first-person outline you can adapt. Fill in the placeholders with your real details, do not invent them.

> I ran the attack against my own access point, [your SSID], on [date]. wifi-bf tried the SecLists top 100,000 common-password list against it. [State the result: it cracked after N attempts, or it ran the full list without success.] I then built the defensive side into NetPane, my own network troubleshooting tool. The Wi-Fi Audit panel reads the encryption on every nearby access point and flags weak ones, scores a passphrase, and checks it against the exact wordlist an attacker would use. Testing [your SSID]'s passphrase in the panel showed [the result], which matches the attack: [if it cracked, the passphrase was in the list; if it did not, the passphrase was not in the list and the entropy was high enough to hold].

Two findings are worth calling out separately, because they came out of the setup and they show you were paying attention. First, the network you were testing on filters GitHub's raw CDN while leaving general HTTPS open, which is why the tool's own wordlist download failed at first and why the install script falls back to a mirror. That is a real egress-filtering observation. Second, whether or not the crack succeeds, the panel gives you the remediation in one line: if the passphrase is on a common list, replace it with something long and random; if it is not, you have evidence the network resists the simplest attack.

That is the honest version of the project, and it reads better than a cracker with a nice button on it. One tool demonstrates the risk, the other measures and fixes it.
