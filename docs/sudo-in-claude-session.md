# Running sudo / GUI tests from a Claude session on this box

`sudo` has no tty under the `!` prefix, and the Bash tool can't type a password,
so a plain `! sudo …` fails with "a terminal is required to read the password".

**Fix:** point `SUDO_ASKPASS` at a `zenity --password` helper and use `sudo -A`,
invoked via the `!` prefix so it runs in the user's session (DISPLAY/DBUS are
present, so GUI dialogs work):

```sh
! SUDO_ASKPASS=/path/to/askpass.sh sudo -A bash some-script.sh
```

where `askpass.sh` is:

```sh
#!/bin/sh
exec zenity --password --title="sudo"
```

(See `../phase0/askpass.sh` and `../e2e.sh` for working examples.)

**The agent cannot click GUI dialogs itself.** Interactive GUI tests (zenity
prompts, etc.) must be run by the user via the `!` prefix; the agent prepares the
script and reads back the output.
