# GNU Privacy Guard - Short Reference

> [!TIP]
> For a more detailed treatise check [Dr. Duh's
> YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

## Backup Storage

### Creation

For a local and secure backup a small encrypted file will suffice. <br>
Additional perk: you can put multiple such files on a drive.

```
sudo dd if=/dev/urandom of=store.dat bs=1M count=25
sudo cryptsetup -c aes-xts-plain64 -s 512 -h sha512 -y luksFormat store.dat
sudo cryptsetup luksOpen store.dat backup
sudo mkfs.ext4 /dev/mapper/backup
sudo cryptsetup luksClose backup
```

Now just put this file on a safely-stored thumb drive.

### Mounting

> [!TIP]
> Do this in the secure live system (e.g. [tails](https://tails.net/index.de.html),
> see below).

Mount encrypted file as non-root user

```
udisksctl mount -b /dev/mmcblk0p1 backup
sudo cryptsetup luksOpen store.dat backup
udisksctl mount -b /dev/mapper/backup

# -> do your stuff

udisksctl unmount -b /dev/mapper/backup
sudo cryptsetup luksClose backup
udisksctl unmount -b /dev/mmcblk0p1
```

### Versioning

It might make sense to version all backups.

```
git init

# don't use the `--global` option, we want to store it locally in `.git/config`
git config user.email <email>
git config user.name <name>
git config commit.gpgsign true

git log --show-signature
```

## Environment

Make your life easy and use [Tails](https://tails.net/index.de.html). Live
systems like Arch Linux which directly start in a root shell won't work well
with GPG (see [here](https://wiki.archlinux.org/title/GnuPG#su)).

> [!IMPORTANT]
> For Tails, don't forget to enable the administrator password in additional
> settings during startup!

Create temporary working directory (run as user)

```bash
export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)
```

Harden GPG config

```
wget -O $GNUPGHOME/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf
```

or copy existing one from backup drive to avoid early network connections.

> [!IMPORTANT]
> In the current version of DrDuh's config, the `armor` option is set, i.e. gpg
> exports are not in binary format anymore by default. Keep in mind to add the
> `--no-armor` flag when needed.

## Generating

> [!NOTE]
> (Arguably) best practice:
>
> - primary keys should never expire
> - subkeys are valid for not longer than 1 year

Parent key (pure ed25519 / cv25519)

```bash
gpg --quick-generate-key 'Your Name <your.email@example.com>' ed25519 cert never
```

Subkeys

```bash
export KEYID='<fingerprint>'
gpg --quick-add-key $KEYID ed25519 sign 1y
gpg --quick-add-key $KEYID cv25519 encr 1y
gpg --quick-add-key $KEYID ed25519 auth 1y
```

Add additional UIDS

```
gpg --expert --edit-key $KEYID
gpg> adduid
```

Select UIDS and fully trust them (will not show correct "ultimate trust" until
all changes have been saved)

```
gpg> uid 2
gpg> uid 3
gpg> trust
Your decision? 5
```

Make other UID primary

```
gpg> uid 3
gpg> primary
```

Save and quit

```
gpg> save
gpg> quit
```

Quality check (requires `openpgp-tools` package)

```bash
gpg --export $KEYID | hokey lint
```

## Exporting

Create export folder (or directly use folder on backup drive)

```bash
mkdir $GNUPGHOME/exports
```

> [!NOTE]
> Exports of the same key will always produce different files because of
> salting, see [here](https://bbs.archlinux.org/viewtopic.php?id=263337).

All secret keys incl. subkeys

```bash
gpg --armor --export-secret-keys $KEYID > primary.asc
```

"Laptop keypair" - i.e. only subkeys but no primary

```bash
gpg --armor --export-secret-subkeys $KEYID > subs.asc
```

> [!TIP]
> Use the `backup` option to export all necessary information to restore the
> secrets keys (including local signatures) _but NOT_ the trust database entry,
> check [docs](https://gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html).

```bash
gpg --armor --export-options export-backup --export-secret-keys $KEYID > full_backup.asc

# import would read
gpg --import-options restore[,keep-ownertrust] --import full_backup.asc
```

Paperkey and QR code (examples [here](https://wiki.archlinux.org/title/Paperkey))
can optionally be generated from binary secret keys

```bash
sudo pacman -S paperkey qrencode
gpg --no-armor --export-secret-keys $KEYID | paperkey --output paperkey.asc
gpg --no-armor --export-secret-keys $KEYID | paperkey --output-type raw | qrencode --8bit --level H --output paperkey.qr.png
```

Print paperkey (make sure to set a default printer in CUPS)

```
lp -o media=a4 -o portrait -o fit-to-page -o sides=two-sided-long-edge paperkey.asc
```

Paperkey needs public keys for restoration, so export them in their armored and
binary versions

```
gpg --armor --export $KEYID > pubkey.asc
gpg --no-armor --export $KEYID > pubkey.gpg
```

Revocation certificate (with optionally specified reason) in case key gets
compromised (-> select 1)

> [!NOTE]
> By default a generic one is already created in `$GNUPGHOME/openpgp-revocs.d/$KEYID.rev`.

```bash
gpg --gen-revoke $KEYID > revoke_compromised.asc
```

Export trust database

> [!IMPORTANT]
> Exported trust values are equal to trust level + 1:
>
> Trust Level 1 (export: 2) = I don't know or won't say <br>
> Trust Level 2 (export: 3) = I do NOT trust <br>
> Trust Level 3 (export: 4) = I trust marginally <br>
> Trust Level 4 (export: 5) = I trust fully <br>
> Trust Level 5 (export: 6) = I trust ultimately <br>

```bash
gpg --export-ownertrust > export/ownertrust.txt
```

Private keys are stored in `$GNUPGHOME/private-keys-v1.d/`, check with

```bash
gpg -K --with-keygrip
```

Push to proper keyserver

```bash
gpg --export $KEYID | curl -T - https://keys.openpgp.org
# on tails via Tor
gpg --export $KEYID | torify curl -T - https://keys.openpgp.org
```

Legacy keyservers

```bash
gpg --keyserver hkps://keyserver.ubuntu.com --send-keys $KEYID
gpg --keyserver https://pgp.mit.edu --send-keys $KEYID
```

> [!TIP]
> Now is a good time to test recovery of the generated backup exports,
> in particular for the paperkey version. Just create another temporary
> GNUPGHOME and run the import commands listed below.

## Recovery

Process

1. requires _binary_ pubkey in addition (de-armor if required)
2. needs `export GPG_TTY=$(tty)` for `gpg --import` on live system

From QR code

```bash
zbarimg -1 --raw -q -Sbinary paperkey.qr.png | paperkey --pubring pubkey.gpg | gpg --import
```

From paperkey text file

```bash
paperkey --pubring pubkey.gpg --secrets paperkey.asc | gpg --import
```

Optionally use some OCR software like
[OCRmyPDF / tesseract](https://github.com/ocrmypdf/OCRmyPDF) to convert printed sheets into
`paperkey.asc` file.

## Extending Expiration

> [!IMPORTANT]
> The expiration date is a public key attribute only (the private keys never expire).

Boot into secure environment and mount backup drive as explained in the
respective sections above.

Create temporary GPG working directory

```
export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)
cp <decrypted_backup_drive>/gpg.conf $GNUPGHOME
```

Import expired key

```bash
# pinentry setting might be necessary when in TTY
gpg [--pinentry-mode loopback] --import full_backup.asc
```

List expired subkeys

```bash
gpg --list-options show-unusable-subkeys -K
```

Extend expiration dates

```bash
gpg --edit-key $KEYID
```

> [!NOTE]
> (Arguably) best practice:
>
> - primary keys should never expire
> - subkeys are valid for not longer than 1 year

Primary key

```
gpg> expire
gpg> never
gpg> save
```

Subkeys

```
# use key 0 to deselect all
gpg> key 1
gpg> key 2
gpg> key 3
gpg> expire
gpg> 1y
gpg> save
```

Public keys have changed, so export and upload them (secret keys can leave
untouched!)

```
# all relevant exports
gpg --armor --export-secret-keys --export-options export-backup $KEYID > full_backup.asc
gpg --armor --export $KEYID > pubkey.asc
gpg --no-armor --export $KEYID > pubkey.gpg
```

> [!NOTE]
> When not under version control, it might be a good idea to give the exports a
> different name like
>
> ```
> gpg --armor --export $KEYID > $KEYID-$(date +%F).asc
> ```

On each host import updated public key

```
# from keyserver
gpg [--keyserver hkps://keys.openpgp.org] --recv $KEYID
# or alternatively
gpg [--keyserver hkps://keys.openpgp.org] --refresh-keys
# or from file
gpg --import pubkey.asc
```

## YubiKey

### Setup

> [!IMPORTANT]
> You can safely enable KDF if you're planning to use the key on Android with
> OpenKeyChain.<br>
> See https://github.com/open-keychain/open-keychain/issues/2368.

Confirm yubikey is genuine: https://www.yubico.com/genuine/

Prepare yubikey (set PIN + Admin Pin but leave reset code disabled)

```
# factory pin: 123456
# factory admin pin: 12345678
gpg --card-edit
gpg/card> admin
gpg/card> name
gpg/card> kdf-setup
gpg/card> passwd
```

Transfer keys

```bash
gpg --edit-key $KEYID
```

```
gpg> key 1
gpg> keytocard
Your selection? 1

gpg> key 1
gpg> key 2
gpg> keytocard
Your selection? 2

gpg> key 2
gpg> key 3
gpg> keytocard
Your selection? 3

gpg> save
gpg> quit
```

Verify all subkeys start with `ssb>`

```bash
gpg -K
```

Add pubkey URL to yubikey

```
gpg --edit-card
gpg/card> admin
gpg/card> url # https://keys.openpgp.org/vks/v1/by-fingerprint/<fingerprint>
gpg/card> quit
```

Remove and reinsert yubikey, then check its status

```bash
gpg --card-status
```

Enforce touch for GPG operations

```bash
# on arch
sudo pacman -S yubikey-manager
sudo systemctl start pcscd.servicd
# on tails
sudo apt install yubikey-manager
```

```bash
ykman openpgp keys set-touch aut on
ykman openpgp keys set-touch sig on
ykman openpgp keys set-touch enc on
```

## New Host

Basically follow the "Using keys" section in [Dr. Duh's
guide](https://github.com/drduh/YubiKey-Guide?tab=readme-ov-file#using-keys).

Assuming the pubkey URL field has been set in the yubikey.

Fetch public key and deploy subkey references pointing to yubikey

```bash
gpg --edit-card
```

```
gpg/card> fetch
gpg: requesting key from '<URL>'
gpg: /home/pi/.gnupg/trustdb.gpg: trustdb created
gpg: key FF3E7D88647EBCDB: public key "Dr Duh <doc@duh.to>" imported
gpg: Total number processed: 1
gpg: imported: 1
gpg/card> quit
```

---

Otherwise download the public keys from a keyserver or local computer,
import with

```bash
gpg --search email.address@web.com
gpg --import $KEYID
```

and then only run

```bash
gpg --card-status
```

to create the references.

---

Set trust level

```bash
export KEYID='<fingerprint>'
gpg --edit-key $KEYID
```

```
gpg> trust (5)
gpg> quit
```

Yubikey and GPG keys should now show these symbols in front of the secret keys:

```bash
gpg -K
gpg --card-status
```

```
sec# ed25519/0xAABBCCDDEEFF0011
ssb> ed25519/0xAABBCCDDEEFF0022
ssb> ed25519/0xAABBCCDDEEFF0033
ssb> cv25519/0xAABBCCDDEEFF0044
```

### Unblock PIN

After 3 failed attempts yubikey gets blocked. Unblock with

```
# https://github.com/drduh/YubiKey-Guide/issues/168#issuecomment-1379532749
gpg --edit-card
admin
passwd # select "2 - unblock PIN" and enter admin PIN
gpg --card-status # verify "PIN retry counter" says again "3 0 3"
```

### Android

For use with the [Android Password Store](https://passwordstore.app/):

1. Install [OpenKeyChain](https://www.openkeychain.org/)
2. Remove Google Authenticator, it will block APS's NFC connection
3. Generate SSH key in APS and add it as "deploy key" to the shared repo
4. Add recipient to gopass
5. Clone repo on phone and unlock secrets like a boss

## SSH Agent

### Setup

GPG can also act as SSH agent. To enable, add in
`~/.gnupg/gpg-agent.conf`

```
enable-ssh-support
```

and reload the agent

```
gpg-connect-agent reloadagent /bye
```

In zsh you might want to use [this oh-my-zsh
plugin](https://github.com/ohmyzsh/ohmyzsh/blob/master/plugins/gpg-agent/gpg-agent.plugin.zsh) for convenience. It
takes care of properly starting the agent and exporting
`SSH_AUTH_SOCK`.

### Import SSH PrivKey

> [!TIP]
> To understand the difference between GPG and SSH fingerprints, consult
> [this great blogpost](https://blog.djoproject.net/2020/05/03/main-differences-between-a-gnupg-fingerprint-a-ssh-fingerprint-and-a-keygrip/).

Native SSH keys created with e.g.

```
ssh-keygen -a 100 -t ed25519 -f ~/.ssh/customer/sshkey -C "<email>::<customer>::$(date +'%Y-%m-%d')"
```

are added to the agent via

```bash
# sets the cache lifetime to 3600s, use -c for always confirm
ssh-add -c -t 3600 ~/.ssh/id_rsa
```

This converts the SSH key _irreversibly_ into GPG format and stores it
separately from the original private key as

```bash
cat ~/.gnupg/private-keys-v1.d/<KEYGRIP>.key
```

The keygrip is basically the same protocol-agnostic ID as calculated for GPG
keys with

```
gpg -K --with-keygrip
```

All enabled SSH keys are listed with their keygrip and selected hashes here:

```bash
cat ~/.gnupg/sshcontrol
-----------------------
# Ed25519 key added on: 2023-02-18 20:43:21
# Fingerprints:  MD5:31:7f:60:ca:e2:25:69:d7:cb:7b:7d:a1:fd:33:28:cc
#                SHA256:USoxG0ZJuMMwicxRhjgPpqGPzk5cNKA/0R7o0SOddrc
4F8C61F5B655A3F682A2FBB2ECC5B888F933E421 0 confirm
# Ed25519 key added on: 2023-11-09 20:36:07
# Fingerprints:  MD5:f8:21:2e:ad:14:35:63:74:49:34:a8:fd:bc:55:8b:8b
#                SHA256:uKzAVdF4S3yb5RNe10JbUCmmPdJmp1vf3F1YvTnqbZQ
F97B2173319631EC38520EE3E82780E9A24960B4 3600
```

These hashes (as in SSH fingerprints) can be manually obtained from the
original SSH key with

```bash
ssh-keygen -E sha256 -lf <ssh-pubkey>
ssh-keygen -E md5 -lf <ssh-pubkey>
```

Removing an SSH key involves

1. delete GPG-converted private key `~/.gnupg/private-keys-v1.d/<KEYGRIP>.key`
2. remove corresponding entry in `~/.gnupg/sshcontrol`

### Export SSH PubKey

In order to use an authentication-enabled GPG (sub)key for SSH, run either of
these commands

```bash
ssh-add -L
gpg --export-ssh-key <ID>
```

This will output a public key in SSH format that can be added to
`~/.ssh/authorized_keys` on remote hosts.

## Misc

### GoPass

Make sure to add encryption subkey instead of primary and set

```
export $GOPASS_GPG_OPTS="--no-throw-keyids"
```

in your shell.

### Git Subkeys

When working with subkeys for git commit signatures, add them with trailing
exclamation mark to `~/.gitconfig`, otherwise GPG will use the latest one with
signing capability or resolve to primary.

> [!CAUTION]
> Depending on the shell (e.g. for zsh) you need to escape the exclamation mark
> or use single quotes so it is not interpreted. See https://unix.stackexchange.com/a/234300.

```
# for zsh
git config user.signingkey "1F8375B06B86E11DB5707569FB9D7A2564F37DB4\!"
git config user.signingkey '1F8375B06B86E11DB5707569FB9D7A2564F37DB4!'
```
