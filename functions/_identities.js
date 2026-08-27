// source of truth for hartforge keys.
// add a person: give them a handle, name, and a list of openssh public key lines.
// each key: paste the full pubkey line into `line`, optionally add a label + added date (mm-dd-yyyy).
// the .keys endpoint serves `line` verbatim; fingerprints/types are derived at runtime.

export const identities = {
  patrick: {
    name: "Patrick Hart",
    handle: "patrick",
    tagline: "hart forge",
    keys: [
      {
        line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMW/LPEPctc8sALGAE7yeHsPfzAFthzpwmhxoX3gvOSU admin@mac-mini",
        label: "patricks-macmini",
        added: "07-21-2026",
      },
      {
        line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDb+e6Z7Y1I27Hd7d1LtgKQZyf/lqGEq/Gg5pQq2QgZx patricks-mbp",
        label: "patricks-mbp",
        added: "07-21-2026",
      },
      {
        line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHcwz3Qo0mmDtJ4TZ3enUn+PFDo4CNJ1p0tOyxwFmY9l patrick@patricks-pc",
        label: "patricks-pc",
        added: "08-27-2026",
      },
    ],
  },
};

export function getIdentity(handle) {
  return identities[handle] || null;
}
