# SSO/WebAuth evaluation

Status: experimental; not installed into the system and not tested against a real VPN.

## Provenance

Base: upstream main d10793b589551b26b06459c1dc891112d94f0e67.

Imported from https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/merge_requests/114
with original authorship retained:

- 0234a0d7179749c5259ae75865f7a2c52eda96d2: webauth and crtext support.
- c3d49db984d3318754e3dececb97f128dccdf0e7: compiler compatibility.
- a50244c2f6c261c4bc7a06351e107ee7cef6e513: systemd user-manager browser launch.

Local additions: protocol regression tests and redaction of INFOMSG contents and
web login URLs from the service's webauth log messages. OpenVPN's own logs and
other existing authentication logging may still contain sensitive material.

## Reproduce the build

On Fedora, dependencies are listed in .gitlab-ci.yml. Enable both GTK editors:

```sh
./autogen.sh --with-gtk4 --prefix="$PWD/../../work/install"
make -j"$(nproc)"
make check
```

Validation on Fedora 44 / GCC 16: strict warnings-as-errors build passed,
78 existing import/export cases and 9 new protocol cases passed (two test
executables). The new cases exercise the actual service parser, base64 response
encoding (including newline injection), and log redaction without root, D-Bus,
a browser or a VPN endpoint. The service implementation is included in the test
translation unit with its entry point renamed; that entry point is not run.
The helper also passed sh -n and rejects file:// and javascript: inputs.

## Remaining review and integration work

- The browser helper chooses the first desktop process matching its list, not
  the authenticated user who initiated this VPN. Multi-user systems, display
  managers and multiple seats require a reliable user/session association.
- WEB_AUTH flags are parsed but not acted on. Proxy mode needs implementation
  or an explicit unsupported result. No proxy capability is advertised.
- The service does not explicitly process AUTH_PENDING state notifications to
  coordinate its lifecycle with NetworkManager's activation timeout. Validate
  vpn.timeout and server auth timeout together before testing a long MFA flow.
- Helper exit status is ignored by the child watcher; successful spawning does
  not prove that the browser opened. Browser-launch failure needs better feedback.
- Deduplication retains the last URL for the service connection; test renewed
  auth, reconnection, concurrent activation and reuse of the same URL.
- Validate SELinux, GNOME/Wayland and session environment behavior on Fedora.
- Cancellation, network loss, token-based reconnection and ordinary password /
  certificate connections need integration coverage. Existing unit tests do not
  establish these properties.

## Next real-server validation

Use a local .ovpn profile and identify the server product/version. Do not commit
profiles, certificates, keys, tokens or full login URLs. Installation and VPN
activation are separate steps; the current build uses a private prefix and is
not registered with the system NetworkManager.

Prepare a reversible installation or isolated VM, preserve the original package,
and activate a separate test connection. Check initial login, Entra MFA, refusal,
cancel, timeout, reconnect, routes and DNS. Avoid verbose logs containing tokens.
Do not treat a successful build as evidence of successful SSO.
